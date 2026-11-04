//! Signal systemd only after management, HA control and startup withdrawal exist.
use anyhow::{Context, Result};
use std::{ffi::OsStr, os::unix::net::UnixDatagram};

pub fn ready() -> Result<()> {
    if let Some(path) = std::env::var_os("NOTIFY_SOCKET") {
        send(&path).context("notify service readiness")?;
    }
    Ok(())
}

fn send(path: &OsStr) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let socket = UnixDatagram::unbound()?;
    #[cfg(target_os = "linux")]
    if path.as_bytes().first() == Some(&b'@') {
        use std::os::linux::net::SocketAddrExt;
        let address = std::os::unix::net::SocketAddr::from_abstract_name(&path.as_bytes()[1..])?;
        socket.connect_addr(&address)?;
    } else {
        socket.connect(path)?;
    }
    #[cfg(not(target_os = "linux"))]
    socket.connect(path)?;
    socket.send(b"READY=1")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notifies_filesystem_socket() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("notify");
        let listener = UnixDatagram::bind(&path).unwrap();
        send(path.as_os_str()).unwrap();
        let mut message = [0; 64];
        let length = listener.recv(&mut message).unwrap();
        assert_eq!(&message[..length], b"READY=1");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn notifies_abstract_socket() {
        use std::os::linux::net::SocketAddrExt;
        let name = format!("riverlb-notify-{}", std::process::id());
        let address = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
        let listener = UnixDatagram::bind_addr(&address).unwrap();
        send(OsStr::new(&format!("@{name}"))).unwrap();
        let mut message = [0; 64];
        let length = listener.recv(&mut message).unwrap();
        assert_eq!(&message[..length], b"READY=1");
    }
}
