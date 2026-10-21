//! Announce floating address ownership to clients after promotion.
use anyhow::{Context, Result, ensure};
use std::net::IpAddr;
fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for pair in bytes.chunks(2) {
        sum += u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
fn frame(mac: [u8; 6], ip: IpAddr) -> Vec<u8> {
    let mut packet = Vec::new();
    match ip {
        IpAddr::V4(ip) => {
            packet.extend([255; 6]);
            packet.extend(mac);
            packet.extend(0x0806u16.to_be_bytes());
            packet.extend([0, 1, 8, 0, 6, 4, 0, 1]);
            packet.extend(mac);
            packet.extend(ip.octets());
            packet.extend([0; 6]);
            packet.extend(ip.octets());
        }
        IpAddr::V6(ip) => {
            let destination: std::net::Ipv6Addr = "ff02::1".parse().unwrap();
            packet.extend([0x33, 0x33, 0, 0, 0, 1]);
            packet.extend(mac);
            packet.extend(0x86ddu16.to_be_bytes());
            packet.extend([0x60, 0, 0, 0, 0, 32, 58, 255]);
            packet.extend(ip.octets());
            packet.extend(destination.octets());
            let mut message = vec![136, 0, 0, 0, 0x20, 0, 0, 0];
            message.extend(ip.octets());
            message.extend([2, 1]);
            message.extend(mac);
            let mut pseudo = Vec::new();
            pseudo.extend(ip.octets());
            pseudo.extend(destination.octets());
            pseudo.extend(32u32.to_be_bytes());
            pseudo.extend([0, 0, 0, 58]);
            pseudo.extend(&message);
            message[2..4].copy_from_slice(&checksum(&pseudo).to_be_bytes());
            packet.extend(message);
        }
    }
    packet
}
pub async fn announce(
    network: &crate::network::Network,
    before: &crate::network::Network,
) -> Result<()> {
    for address in network
        .self_ips
        .iter()
        .filter(|a| !before.self_ips.contains(a))
    {
        let (ip, _) = crate::network::cidr(&address.address)?;
        let device = network.device(&address.vlan);
        let output = tokio::process::Command::new("/usr/sbin/ip")
            .args(["-j", "link", "show", "dev", device])
            .output()
            .await?;
        ensure!(
            output.status.success(),
            "cannot inspect floating interface for announcement"
        );
        let links: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout)?;
        let link = links.first().context("floating interface missing")?;
        let index = link["ifindex"]
            .as_u64()
            .context("interface index missing")? as i32;
        let mut mac = [0u8; 6];
        let parts = link["address"]
            .as_str()
            .context("Ethernet MAC missing")?
            .split(':')
            .collect::<Vec<_>>();
        ensure!(
            parts.len() == 6,
            "HA floating addresses require Ethernet interfaces"
        );
        for (out, part) in mac.iter_mut().zip(parts) {
            *out = u8::from_str_radix(part, 16)?;
        }
        let bytes = frame(mac, ip);
        tokio::task::spawn_blocking(move || {
            use std::os::fd::{AsRawFd, FromRawFd};
            // Raw Ethernet is needed for gratuitous ARP and unsolicited IPv6 NA.
            let fd = unsafe {
                libc::socket(
                    libc::AF_PACKET,
                    libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                    i32::from(0x0003u16.to_be()),
                )
            };
            ensure!(
                fd >= 0,
                "HA address announcements require CAP_NET_RAW: {}",
                std::io::Error::last_os_error()
            );
            let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
            let mut destination: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
            destination.sll_family = libc::AF_PACKET as u16;
            destination.sll_ifindex = index;
            destination.sll_halen = 6;
            destination.sll_protocol = u16::from_be_bytes([bytes[12], bytes[13]]).to_be();
            destination.sll_addr[..6].copy_from_slice(&bytes[..6]);
            for _ in 0..3 {
                let sent = unsafe {
                    libc::sendto(
                        fd.as_raw_fd(),
                        bytes.as_ptr().cast(),
                        bytes.len(),
                        0,
                        (&destination as *const libc::sockaddr_ll).cast(),
                        std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
                    )
                };
                ensure!(
                    sent == bytes.len() as isize,
                    "floating address announcement failed: {}",
                    std::io::Error::last_os_error()
                );
            }
            anyhow::Ok(())
        })
        .await??;
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn announcements_have_correct_arp_and_ipv6_na_fields() {
        let mac = [2, 0, 0, 0, 0, 1];
        let arp = frame(mac, "192.0.2.70".parse().unwrap());
        assert_eq!(arp.len(), 42);
        assert_eq!(&arp[28..32], &[192, 0, 2, 70]);
        assert_eq!(&arp[38..42], &[192, 0, 2, 70]);
        let ip: std::net::Ipv6Addr = "2001:db8::70".parse().unwrap();
        let na = frame(mac, ip.into());
        assert_eq!(na.len(), 86);
        assert_eq!(na[21], 255);
        assert_eq!(na[54], 136);
        assert_eq!(na[58], 0x20);
        assert_eq!(&na[62..78], &ip.octets());
        let mut pseudo = Vec::new();
        pseudo.extend(&na[22..54]);
        pseudo.extend(32u32.to_be_bytes());
        pseudo.extend([0, 0, 0, 58]);
        pseudo.extend(&na[54..]);
        assert_eq!(checksum(&pseudo), 0);
    }
}
