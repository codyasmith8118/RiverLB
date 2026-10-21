# Server TLS profiles

Local Traffic → Profiles → Server TLS creates reusable backend TLS settings. Set
the profile name, TLS server name and trusted CA certificate PEM file path. On a
virtual server, assign **Backend server TLS profile** and Save and apply. Inline
backends and named pools both work; profiles are assigned per virtual server.

```toml
[[server_tls_profiles]]
name = "home-https"
server_name = "app.home.example"
ca_certificate = "/etc/riverlb/home-ca.pem"

# In an existing [[virtual_servers]]:
# server_tls_profile = "home-https"
```

Every backend connection is wrapped in Rustls TLS. Certificates must chain to an
explicit trust anchor and match `server_name`, including validity checks. A blank
name verifies the destination member IP. The read-only `server_tls` default uses
Ubuntu's system CA bundle and this per-member IP verification; clone it to customize
trust or DNS SNI. DNS
names send SNI; IP names verify IP identities. Names cannot include a port. No
skip-verification option exists. A private home CA or a trusted self-signed leaf
can be supplied in PEM form; use only intended trust anchors. Missing/empty trust
files, duplicate profiles and unknown assignments fail validation.

Incoming TLS and backend TLS are independent. A virtual server can receive plain
TCP and connect to TLS backends, or terminate incoming TLS and create a separate
verified TLS connection to its backend. To keep encrypted client TLS opaque all
the way to the backend, use passthrough without either termination/profile.

The complete backend source selection, TCP connection and TLS handshake share
`connect_timeout_ms`. Automap/SNAT/self-IP binding still occurs before wrapping
the socket. Handshake/connect failures close that client connection, increment
failures and immediately mark the selected member down. No automatic retry is
performed. Traffic bytes count forwarded application data, excluding TLS overhead.

Default TCP and explicitly named TCP health checks perform verified TLS handshakes
when a Server TLS profile is assigned, bounded by the monitor deadline. HTTP and
HTTPS readiness monitors retain their independently configured protocol/trust:
use an HTTPS monitor for application checks on a TLS member. An HTTPS readiness
monitor does not automatically inherit Server TLS profile settings.

Trust is loaded once per runtime generation, before committing the configuration.
Changing the CA file alone does not update existing runtime trust; apply or
restart to reload it. Existing sessions keep their original TLS configurations
when applying changes. Back up the external trust PEM files along with database
configuration. These are public trust files, not private-key assets; the current
certificate inventory is used for incoming termination, not this trust store.

Backend mTLS, managed CA objects,
per-member SNI names, custom cipher/session policies, ALPN selection, TLS connection
reuse and broader behavior qualification remain unsupported. Forwarding remains
opaque TCP; this feature does not add HTTP request/header routing or cookie
persistence.

`tests/server_tls.py` verifies real encrypted backend traffic and SNI, TLS bridging,
hostname rejection, monitor deadlines, invalid assignments/trust files, hot apply
and durable profiles across restart. Portal tests verify CRUD, assignment and reload.
