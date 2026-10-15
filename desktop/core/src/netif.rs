//! `net_interfaces`: this device's IPv4 addresses for the team listener picker ("다른 기기
//! 접속"). Team sync is direct LAN/VPN only (docs/team-sync.md), so loopback, link-local and
//! down interfaces are left out, and VPN addresses are listed first.

use std::net::Ipv4Addr;

use nix::ifaddrs::getifaddrs;
use nix::net::if_::InterfaceFlags;
use serde::Serialize;

use crate::error::AppError;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum NetKind {
    Vpn,
    Lan,
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NetInterface {
    pub name: String,
    pub ip: String,
    pub kind: NetKind,
}

const VPN_PREFIXES: [&str; 9] = [
    "utun",
    "tun",
    "tap",
    "wg",
    "ppp",
    "ipsec",
    "tailscale",
    "zt",
    "nordlynx",
];

/// VPN when the interface is a tunnel (by name or point-to-point) or the address is in the
/// CGNAT range Tailscale and similar overlays use; LAN for RFC 1918 addresses; other otherwise.
pub fn classify(name: &str, ip: Ipv4Addr, point_to_point: bool) -> NetKind {
    let octets = ip.octets();
    let cgnat = octets[0] == 100 && (64..128).contains(&octets[1]);
    if point_to_point || cgnat || VPN_PREFIXES.iter().any(|p| name.starts_with(p)) {
        NetKind::Vpn
    } else if ip.is_private() {
        NetKind::Lan
    } else {
        NetKind::Other
    }
}

/// Whether an address is worth offering to other devices at all.
pub fn offerable(ip: Ipv4Addr) -> bool {
    !(ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_multicast()
        || ip.is_broadcast())
}

pub fn list() -> Result<Vec<NetInterface>, AppError> {
    let addrs = getifaddrs()
        .map_err(|e| AppError::io("interfaces_unavailable", &std::io::Error::from(e)))?;
    let mut out: Vec<NetInterface> = Vec::new();
    for ifa in addrs {
        if !ifa.flags.contains(InterfaceFlags::IFF_UP)
            || ifa.flags.contains(InterfaceFlags::IFF_LOOPBACK)
        {
            continue;
        }
        let Some(sin) = ifa.address.as_ref().and_then(|a| a.as_sockaddr_in()) else {
            continue;
        };
        let ip = sin.ip();
        if !offerable(ip) {
            continue;
        }
        let kind = classify(
            &ifa.interface_name,
            ip,
            ifa.flags.contains(InterfaceFlags::IFF_POINTOPOINT),
        );
        let entry = NetInterface {
            name: ifa.interface_name.clone(),
            ip: ip.to_string(),
            kind,
        };
        if !out.contains(&entry) {
            out.push(entry);
        }
    }
    out.sort_by(|a, b| (a.kind, &a.name, &a.ip).cmp(&(b.kind, &b.name, &b.ip)));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classification() {
        let ip = |s: &str| s.parse::<Ipv4Addr>().unwrap();
        assert_eq!(classify("utun4", ip("10.8.0.2"), false), NetKind::Vpn);
        assert_eq!(classify("wg0", ip("192.168.50.2"), false), NetKind::Vpn);
        assert_eq!(classify("en0", ip("100.101.1.2"), false), NetKind::Vpn);
        assert_eq!(classify("ppp0", ip("203.0.113.9"), true), NetKind::Vpn);
        assert_eq!(classify("en0", ip("192.168.1.20"), false), NetKind::Lan);
        assert_eq!(classify("eth0", ip("10.0.0.5"), false), NetKind::Lan);
        assert_eq!(classify("eth0", ip("172.20.1.1"), false), NetKind::Lan);
        assert_eq!(classify("en0", ip("100.128.0.1"), false), NetKind::Other);
        assert_eq!(classify("en0", ip("203.0.113.9"), false), NetKind::Other);
        assert!(!offerable(ip("127.0.0.1")));
        assert!(!offerable(ip("169.254.10.1")));
        assert!(!offerable(ip("0.0.0.0")));
        assert!(offerable(ip("192.168.1.20")));
    }

    #[test]
    fn listing_has_no_loopback_and_is_sorted() {
        let list = list().unwrap();
        assert!(list.iter().all(|i| i.ip != "127.0.0.1"));
        assert!(list.windows(2).all(|w| w[0].kind <= w[1].kind));
        let json = serde_json::to_value(&list).unwrap();
        for item in json.as_array().unwrap() {
            assert!(["vpn", "lan", "other"].contains(&item["kind"].as_str().unwrap()));
        }
    }
}
