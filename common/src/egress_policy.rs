// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Per-app outbound connection allowlist.
//!
//! An app declares where it may connect with a WIT `@egress` annotation. The
//! runtime folds the list into the app's measured permissions, so it is part
//! of the configuration hash on the app's certificate and anyone verifying the
//! app can read where it is allowed to connect. No declaration means the app
//! may connect anywhere; an empty declaration (`@egress none`) means nowhere.
//!
//! An entry is a host, `*.` followed by a domain, or either with `:port`:
//!
//! - `api.example.org` matches that host on any port.
//! - `api.example.org:8443` matches that host on that port only.
//! - `*.example.org` matches any subdomain of `example.org`, at any depth, but
//!   not `example.org` itself.
//! - An IP literal such as `203.0.113.7` matches only that address. Raw WASI
//!   sockets connect by address, so this is how a socket destination is listed.
//!
//! Hosts compare case-insensitively.

/// Whether `host:port` is permitted by `allowlist`.
pub fn allows(allowlist: &[impl AsRef<str>], host: &str, port: u16) -> bool {
    allowlist.iter().any(|e| entry_allows(e.as_ref(), host, port))
}

fn entry_allows(entry: &str, host: &str, port: u16) -> bool {
    let (pattern, entry_port) = match entry.rsplit_once(':') {
        Some((p, port_str)) => match port_str.parse::<u16>() {
            Ok(n) => (p, Some(n)),
            // Not a port: the entry is malformed and matches nothing.
            Err(_) => return false,
        },
        None => (entry, None),
    };
    if entry_port.is_some_and(|p| p != port) {
        return false;
    }
    let host = host.trim_end_matches('.');
    match pattern.strip_prefix("*.") {
        Some(domain) => {
            // A subdomain: longer than the domain, ending in ".<domain>".
            host.len() > domain.len() + 1
                && host[host.len() - domain.len()..].eq_ignore_ascii_case(domain)
                && host.as_bytes()[host.len() - domain.len() - 1] == b'.'
        }
        None => !pattern.is_empty() && host.eq_ignore_ascii_case(pattern),
    }
}

#[cfg(test)]
mod tests {
    use super::allows;

    const LIST: &[&str] = &["api.example.org", "pay.example.com:8443", "*.cdn.example.net", "203.0.113.7:5432"];

    #[test]
    fn a_host_entry_matches_that_host_on_any_port() {
        assert!(allows(LIST, "api.example.org", 443));
        assert!(allows(LIST, "API.Example.org", 8080));
        assert!(allows(LIST, "api.example.org.", 443));
        assert!(!allows(LIST, "other.example.org", 443));
        assert!(!allows(LIST, "evilapi.example.org", 443));
    }

    #[test]
    fn a_port_entry_matches_that_port_only() {
        assert!(allows(LIST, "pay.example.com", 8443));
        assert!(!allows(LIST, "pay.example.com", 443));
    }

    #[test]
    fn a_wildcard_matches_subdomains_but_not_the_apex() {
        assert!(allows(LIST, "a.cdn.example.net", 443));
        assert!(allows(LIST, "a.b.cdn.example.net", 443));
        assert!(!allows(LIST, "cdn.example.net", 443));
        assert!(!allows(LIST, "xcdn.example.net", 443));
        assert!(!allows(LIST, "cdn.example.net.evil.org", 443));
    }

    #[test]
    fn an_ip_entry_matches_that_address() {
        assert!(allows(LIST, "203.0.113.7", 5432));
        assert!(!allows(LIST, "203.0.113.7", 22));
        assert!(!allows(LIST, "203.0.113.8", 5432));
    }

    #[test]
    fn an_empty_list_allows_nothing() {
        let none: &[&str] = &[];
        assert!(!allows(none, "api.example.org", 443));
    }

    #[test]
    fn a_malformed_entry_matches_nothing() {
        assert!(!allows(&["api.example.org:notaport"], "api.example.org", 443));
        assert!(!allows(&[""], "", 443));
    }
}
