use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use url::Url;

/// AWS / GCP / Azure metadata endpoint. Always blocked even if private
/// IPs are otherwise allowed -- this address is unique to cloud-VM
/// privilege-escalation pivots.
pub(crate) const CLOUD_METADATA_V4: Ipv4Addr = Ipv4Addr::new(169, 254, 169, 254);

/// Validate scheme of a parsed CDP URL.
///
/// Accepts only `https`, plus `http` when `allow_http` is true. Rejects
/// anything else (`file`, `ldap`, `ftp`, ...). Scheme is matched
/// case-insensitively per RFC 3986 §3.1, but `Url::parse` already
/// lowercases it.
pub(crate) fn check_scheme(url: &Url, allow_http: bool) -> Result<(), &'static str> {
    match url.scheme() {
        "https" => Ok(()),
        "http" if allow_http => Ok(()),
        "http" => Err("http_scheme_disallowed"),
        _ => Err("invalid_scheme"),
    }
}

/// Check whether an IP address must be rejected before any TCP connect.
/// Returns `Some(reason)` if blocked, `None` if permitted.
///
/// Blocked classes:
/// - Cloud metadata service (169.254.169.254).
/// - IPv4 loopback (127.0.0.0/8), unspecified (0.0.0.0), broadcast.
/// - IPv4 RFC 1918 private (10/8, 172.16/12, 192.168/16).
/// - IPv4 link-local (169.254/16).
/// - IPv4 CGNAT (100.64/10).
/// - IPv4 documentation (192.0.2/24, 198.51.100/24, 203.0.113/24).
/// - IPv4 benchmarking (198.18/15).
/// - IPv4 multicast (224/4) and reserved future use (240/4).
/// - IPv6 loopback (`::1`), unspecified (`::`).
/// - IPv6 link-local (`fe80::/10`).
/// - IPv6 unique local (`fc00::/7`).
/// - IPv6 multicast (`ff00::/8`).
/// - IPv6 documentation (`2001:db8::/32`).
/// - IPv4-mapped IPv6 inheriting any of the above.
pub(crate) fn ip_block_reason(ip: IpAddr) -> Option<&'static str> {
    match ip {
        IpAddr::V4(v4) => block_reason_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return block_reason_v4(mapped);
            }
            block_reason_v6(v6)
        }
    }
}

fn block_reason_v4(v4: Ipv4Addr) -> Option<&'static str> {
    if v4 == CLOUD_METADATA_V4 {
        return Some("cloud_metadata");
    }
    if v4.is_loopback() {
        return Some("loopback");
    }
    if v4.is_unspecified() {
        return Some("unspecified");
    }
    if v4.is_broadcast() {
        return Some("broadcast");
    }
    if v4.is_private() {
        return Some("private_rfc1918");
    }
    if v4.is_link_local() {
        return Some("link_local");
    }
    if v4.is_multicast() {
        return Some("multicast");
    }
    let octets = v4.octets();
    // CGNAT 100.64.0.0/10 (RFC 6598).
    if octets[0] == 100 && (octets[1] & 0b1100_0000) == 0b0100_0000 {
        return Some("cgnat");
    }
    // Documentation 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24.
    if (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
        || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
        || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
    {
        return Some("documentation");
    }
    // Benchmarking 198.18.0.0/15 (RFC 2544).
    if octets[0] == 198 && (octets[1] == 18 || octets[1] == 19) {
        return Some("benchmarking");
    }
    // Reserved 240.0.0.0/4.
    if octets[0] >= 240 {
        return Some("reserved");
    }
    None
}

fn block_reason_v6(v6: Ipv6Addr) -> Option<&'static str> {
    if v6.is_loopback() {
        return Some("loopback");
    }
    if v6.is_unspecified() {
        return Some("unspecified");
    }
    if v6.is_multicast() {
        return Some("multicast");
    }
    let segments = v6.segments();
    // Link-local fe80::/10.
    if (segments[0] & 0xffc0) == 0xfe80 {
        return Some("link_local");
    }
    // Unique local fc00::/7.
    if (segments[0] & 0xfe00) == 0xfc00 {
        return Some("unique_local");
    }
    // Documentation 2001:db8::/32.
    if segments[0] == 0x2001 && segments[1] == 0x0db8 {
        return Some("documentation");
    }
    None
}

/// Sync pre-DNS literal-IP check. Any literal IPv4 or IPv6 host is
/// rejected at URL-validation time, regardless of whether the address
/// falls in a private or public range. OAuth operators must use DNS
/// hostnames; post-DNS runtime checks remain the responsibility of the
/// fetch path.
pub(crate) fn check_url_literal_ip(url: &Url) -> Option<&'static str> {
    match url.host()? {
        url::Host::Ipv4(_) => Some("literal IPv4 addresses are forbidden; use a DNS hostname"),
        url::Host::Ipv6(_) => Some("literal IPv6 addresses are forbidden; use a DNS hostname"),
        url::Host::Domain(_) => None,
    }
}

/// Sync combined redirect-target check. Refuses:
/// - URLs with any userinfo (`username()` non-empty OR `password().is_some()`);
/// - URLs whose literal IP falls in a blocked range (see `ip_block_reason`).
///
/// Used inside `reqwest::redirect::Policy::custom` closures in both
/// `OauthHttpClient::build` and `JwksCache::new`. Does NOT perform DNS.
pub(crate) fn redirect_target_reason(url: &Url) -> Option<&'static str> {
    if !url.username().is_empty() || url.password().is_some() {
        return Some("userinfo (credentials in URL) forbidden");
    }
    match url.host()? {
        url::Host::Ipv4(ip) => ip_block_reason(IpAddr::V4(ip)),
        url::Host::Ipv6(ip) => ip_block_reason(IpAddr::V6(ip)),
        url::Host::Domain(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use url::Url;

    use super::{check_scheme, ip_block_reason};

    #[test]
    fn https_always_allowed() {
        let url = Url::parse("https://crl.example/ca.crl").expect("parse");
        assert!(check_scheme(&url, false).is_ok());
        assert!(check_scheme(&url, true).is_ok());
    }

    #[test]
    fn http_gated_by_flag() {
        let url = Url::parse("http://crl.example/ca.crl").expect("parse");
        assert_eq!(check_scheme(&url, false), Err("http_scheme_disallowed"));
        assert!(check_scheme(&url, true).is_ok());
    }

    #[test]
    fn other_schemes_rejected() {
        for raw in ["ldap://x/", "file:///etc/passwd", "ftp://x/", "gopher://x/"] {
            let url = Url::parse(raw).expect("parse");
            assert_eq!(check_scheme(&url, true), Err("invalid_scheme"));
        }
    }

    #[test]
    fn cloud_metadata_blocked() {
        assert_eq!(
            ip_block_reason(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))),
            Some("cloud_metadata")
        );
    }

    #[test]
    fn loopback_blocked() {
        assert_eq!(
            ip_block_reason(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            Some("loopback")
        );
        assert_eq!(
            ip_block_reason(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            Some("loopback")
        );
    }

    #[test]
    fn rfc1918_blocked() {
        for raw in [[10, 0, 0, 1], [172, 16, 0, 1], [192, 168, 1, 1]] {
            let ip = IpAddr::V4(Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3]));
            assert_eq!(ip_block_reason(ip), Some("private_rfc1918"), "{ip}");
        }
    }

    #[test]
    fn link_local_blocked_v4_v6() {
        assert_eq!(
            ip_block_reason(IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1))),
            Some("link_local")
        );
        assert_eq!(
            ip_block_reason(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1))),
            Some("link_local")
        );
    }

    #[test]
    fn cgnat_blocked() {
        assert_eq!(
            ip_block_reason(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))),
            Some("cgnat")
        );
        assert_eq!(
            ip_block_reason(IpAddr::V4(Ipv4Addr::new(100, 127, 255, 254))),
            Some("cgnat")
        );
    }

    #[test]
    fn documentation_and_benchmarking_blocked() {
        for raw in [[192, 0, 2, 1], [198, 51, 100, 1], [203, 0, 113, 1]] {
            let ip = IpAddr::V4(Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3]));
            assert_eq!(ip_block_reason(ip), Some("documentation"), "{ip}");
        }
        assert_eq!(
            ip_block_reason(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1))),
            Some("benchmarking")
        );
    }

    #[test]
    fn unique_local_v6_blocked() {
        assert_eq!(
            ip_block_reason(IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1))),
            Some("unique_local")
        );
    }

    #[test]
    fn ipv4_mapped_v6_inherits_block() {
        let mapped = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x7f00, 0x0001));
        assert_eq!(ip_block_reason(mapped), Some("loopback"));
    }

    #[test]
    fn public_ips_allowed() {
        assert_eq!(ip_block_reason(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))), None);
        assert_eq!(ip_block_reason(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))), None);
        assert_eq!(
            ip_block_reason(IpAddr::V6(Ipv6Addr::new(
                0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111
            ))),
            None
        );
    }
}
