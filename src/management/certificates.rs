//! Certificate inventory and CSR endpoints for both managed stores.
//! Routing stays under the parent management authentication middleware.
use super::{ApiResult, error};
use crate::control::Control;
use axum::{
    Extension, Json, Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CertificateImport {
    name: String,
    certificate: String,
    private_key: String,
}
async fn certificate_self_signed(
    State(control): State<Arc<Control>>,
    Extension(scope): Extension<crate::certificates::StoreKind>,
    Extension(actor): Extension<String>,
    Json(request): Json<crate::certificates::Generate>,
) -> ApiResult {
    tokio::spawn(async move {
        crate::certificates::validate_name(&request.name)
            .map_err(|e| error(StatusCode::UNPROCESSABLE_ENTITY, e.to_string()))?;
        let _generation = control.generation.lock().await;
        if control.store.certificate_pem_in(scope, &request.name).await
            .map_err(|e| error(StatusCode::SERVICE_UNAVAILABLE, e.to_string()))?.is_some()
        {
            return Err(error(StatusCode::CONFLICT,
                "Certificate already exists; select it or choose another name".into()));
        }
        let (pem, key) = request.self_signed()
            .map_err(|e| error(StatusCode::UNPROCESSABLE_ENTITY, e.to_string()))?;
        control.store.import_certificate_in(scope, &request.name, &pem, &key, &actor).await
            .map_err(|e| error(StatusCode::UNPROCESSABLE_ENTITY, e.to_string()))?;
        Ok(Json(json!({"name":request.name,"message":"Self-signed certificate created; clients must trust it"})))
    }).await.map_err(|_| error(StatusCode::SERVICE_UNAVAILABLE, "Certificate generation failed".into()))?
}
async fn certificate_list(
    State(control): State<Arc<Control>>,
    Extension(scope): Extension<crate::certificates::StoreKind>,
) -> ApiResult {
    let runtime = control.generation.lock().await.runtime.clone();
    let config = &runtime.config;
    let objects = control.store.certificates_in(scope).await.map_err(|_| {
        error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Certificate inventory unavailable".into(),
        )
    })?;
    let objects = objects
        .into_iter()
        .map(|metadata| {
            let name = metadata.name.clone();
            let mut object = serde_json::to_value(metadata).expect("certificate metadata");
            let mut used = if scope == crate::certificates::StoreKind::VirtualServer {
                config
                    .virtual_servers
                    .iter()
                    .filter(|v| {
                        v.certificate.as_deref() == Some(&name)
                            || v.sni_certificates.values().any(|c| c == &name)
                    })
                    .map(|v| v.name.clone())
                    .collect::<Vec<_>>()
            } else {
                Vec::new()
            };
            if scope == crate::certificates::StoreKind::VirtualServer {
                used.extend(
                    config
                        .domain_routes
                        .iter()
                        .filter(|r| r.certificate.as_deref() == Some(&name))
                        .map(|r| format!("Domain route: {}", r.name)),
                );
            }
            if scope == crate::certificates::StoreKind::Device
                && config.management_certificate.as_deref() == Some(&name)
            {
                used.push("Management HTTPS".into());
            }
            object["store"] = json!(scope);
            object["used_by"] = json!(used);
            object
        })
        .collect::<Vec<_>>();
    Ok(Json(json!(objects)))
}
async fn certificate_import(
    State(control): State<Arc<Control>>,
    Extension(scope): Extension<crate::certificates::StoreKind>,
    Extension(actor): Extension<String>,
    Json(import): Json<CertificateImport>,
) -> ApiResult {
    // Complete the mutation even if the initiating browser disconnects.
    tokio::spawn(async move {
    control
        .store
        .import_certificate_in(
            scope,
            &import.name,
            &import.certificate,
            &import.private_key,
            &actor,
        )
        .await
        .map_err(|e| error(StatusCode::UNPROCESSABLE_ENTITY, e.to_string()))?;
    Ok(Json(
        json!({"name":import.name,"message":"Imported; assign this certificate in the configuration draft and apply"}),
    ))
    }).await.map_err(|_| error(StatusCode::SERVICE_UNAVAILABLE,"Management mutation failed".into()))?
}
async fn certificate_delete(
    State(control): State<Arc<Control>>,
    Extension(scope): Extension<crate::certificates::StoreKind>,
    Extension(actor): Extension<String>,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> ApiResult {
    // Complete the mutation even if the initiating browser disconnects.
    tokio::spawn(async move {
    // Serialize deletion against apply: an object cannot disappear between resolve and commit.
    let generation = control.generation.lock().await;
    let config = &generation.runtime.config;
    if (scope == crate::certificates::StoreKind::Device && config.management_certificate.as_deref() == Some(&name))
        || (scope == crate::certificates::StoreKind::VirtualServer && (config.domain_routes.iter().any(|r|r.certificate.as_deref()==Some(&name)) || config.virtual_servers.iter().any(|v| v.certificate.as_deref()==Some(&name) || v.sni_certificates.values().any(|c|c==&name))))
    {
        return Err(error(StatusCode::CONFLICT,"Certificate is referenced by the active configuration; remove its assignments and apply first".into()));
    }
    match control.store.delete_certificate_in(scope, &name, &actor).await {
        Ok(true) => Ok(Json(json!({"deleted":name}))),
        Ok(false) => Err(error(StatusCode::NOT_FOUND, "Unknown certificate".into())),
        Err(_) => Err(error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Certificate deletion failed".into(),
        )),
    }
    }).await.map_err(|_| error(StatusCode::SERVICE_UNAVAILABLE,"Management mutation failed".into()))?
}
async fn certificate_pem(
    State(control): State<Arc<Control>>,
    Extension(scope): Extension<crate::certificates::StoreKind>,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> Response {
    match control.store.certificate_pem_in(scope, &name).await {
        Ok(Some(pem)) => ([("content-type", "application/x-pem-file")], pem).into_response(),
        Ok(None) => error(StatusCode::NOT_FOUND, "Unknown certificate".into()).into_response(),
        Err(_) => error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Certificate export unavailable".into(),
        )
        .into_response(),
    }
}
pub(super) fn router(base: &str, scope: crate::certificates::StoreKind) -> Router<Arc<Control>> {
    Router::new()
        .route(base, get(certificate_list).post(certificate_import))
        .route(
            &format!("{base}/self-signed"),
            post(certificate_self_signed),
        )
        .route(&format!("{base}/requests"), get(csr_list).post(csr_create))
        .route(
            &format!("{base}/requests/{{name}}"),
            get(csr_pem).delete(csr_delete),
        )
        .route(
            &format!("{base}/requests/{{name}}/complete"),
            post(csr_complete),
        )
        .route(
            &format!("{base}/{{name}}"),
            axum::routing::delete(certificate_delete),
        )
        .route(&format!("{base}/{{name}}/pem"), get(certificate_pem))
        .route(
            &format!("{base}/objects/{{name}}/pem"),
            get(certificate_pem),
        )
        .route(
            &format!("{base}/objects/{{name}}"),
            axum::routing::delete(certificate_delete),
        )
        .layer(Extension(scope))
}
async fn csr_list(
    State(control): State<Arc<Control>>,
    Extension(scope): Extension<crate::certificates::StoreKind>,
) -> ApiResult {
    control
        .store
        .certificate_requests(scope)
        .await
        .map(Json)
        .map_err(|e| error(StatusCode::SERVICE_UNAVAILABLE, e.to_string()))
}
async fn csr_create(
    State(control): State<Arc<Control>>,
    Extension(scope): Extension<crate::certificates::StoreKind>,
    Extension(actor): Extension<String>,
    Json(request): Json<crate::certificates::Generate>,
) -> ApiResult {
    tokio::spawn(async move {
        let _generation=control.generation.lock().await;
        let csr=control.store.create_certificate_request(scope,&request,&actor).await.map_err(|e|error(StatusCode::UNPROCESSABLE_ENTITY,e.to_string()))?;
        Ok(Json(json!({"name":request.name,"csr":csr,"message":"CSR created; submit it to your CA and import the signed certificate into this request"})))
    }).await.map_err(|_|error(StatusCode::SERVICE_UNAVAILABLE,"CSR generation failed".into()))?
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedCertificate {
    certificate: String,
}
async fn csr_complete(
    State(control): State<Arc<Control>>,
    Extension(scope): Extension<crate::certificates::StoreKind>,
    Extension(actor): Extension<String>,
    axum::extract::Path(name): axum::extract::Path<String>,
    Json(request): Json<SignedCertificate>,
) -> ApiResult {
    tokio::spawn(async move {
        let _generation = control.generation.lock().await;
        control
            .store
            .complete_certificate_request(scope, &name, &request.certificate, &actor)
            .await
            .map_err(|e| error(StatusCode::UNPROCESSABLE_ENTITY, e.to_string()))?;
        Ok(Json(
            json!({"name":name,"message":"Signed certificate imported; assign it and apply"}),
        ))
    })
    .await
    .map_err(|_| {
        error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Certificate import failed".into(),
        )
    })?
}
async fn csr_pem(
    State(control): State<Arc<Control>>,
    Extension(scope): Extension<crate::certificates::StoreKind>,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> Response {
    match control.store.certificate_requests(scope).await {
        Ok(objects) => match objects
            .as_array()
            .and_then(|items| items.iter().find(|item| item["name"] == name))
        {
            Some(item) => (
                [("content-type", "application/pkcs10")],
                item["csr"].as_str().unwrap().to_owned(),
            )
                .into_response(),
            None => error(StatusCode::NOT_FOUND, "Unknown pending CSR".into()).into_response(),
        },
        Err(_) => error(
            StatusCode::SERVICE_UNAVAILABLE,
            "CSR export unavailable".into(),
        )
        .into_response(),
    }
}
async fn csr_delete(
    State(control): State<Arc<Control>>,
    Extension(scope): Extension<crate::certificates::StoreKind>,
    Extension(actor): Extension<String>,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> ApiResult {
    tokio::spawn(async move {
        let _generation = control.generation.lock().await;
        control
            .store
            .delete_certificate_request(scope, &name, &actor)
            .await
            .map_err(|e| error(StatusCode::SERVICE_UNAVAILABLE, e.to_string()))?;
        Ok(Json(json!({"deleted":name})))
    })
    .await
    .map_err(|_| {
        error(
            StatusCode::SERVICE_UNAVAILABLE,
            "CSR deletion failed".into(),
        )
    })?
}
