// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! The NTS servers trusted time is checked against.
//!
//! One server per operator, so any two picked at random come from different
//! operators: national metrology labs, internet exchanges, registries,
//! universities and companies, all in Europe. Each completed an NTS-KE
//! handshake (TLS 1.3, ALPN `ntske/1`, eight cookies) when the list was
//! compiled. Some of them refuse plain NTP, so a plain NTP probe is not a
//! valid health check.
//!
//! The list is compiled in, and therefore measured, and never taken from
//! configuration: whoever can change it can point the enclave at servers
//! they run, and a valid certificate for a hostname one controls is easy to
//! get. Changing it is a runtime roll.
//!
//! Backups that also passed the handshake, for a future roll:
//! `nts.time.nl`, `1.nts.nothingtohide.nl`, `ntp.miuku.net`,
//! `time.cincura.net`, `ntp01.maillink.ch`.

/// `(host, operator)`; NTS-KE on TCP 4460 unless the server redirects.
pub const NTS_SERVERS: [(&str, &str); 10] = [
    ("nts.netnod.se", "Netnod, Sweden"),
    ("ptbtime1.ptb.de", "PTB, Germany"),
    ("ntppool1.time.nl", "TimeNL (SIDN), Netherlands"),
    ("time.cloudflare.com", "Cloudflare, Europe"),
    ("ntp3.fau.de", "FAU Erlangen-Nuernberg, Germany"),
    ("ntp1.cam.ac.uk", "University of Cambridge, UK"),
    ("nts2.ntp.hr", "University of Zagreb FER, Croatia"),
    ("paris.time.system76.com", "System76, France"),
    ("ntp1.rdem-systems.com", "RDEM Systems, France"),
    ("nts.teambelgium.net", "Team Belgium, Belgium"),
];

/// The hostnames alone, in list order.
pub fn hosts() -> [&'static str; 10] {
    let mut out = [""; 10];
    for (i, (h, _)) in NTS_SERVERS.iter().enumerate() {
        out[i] = h;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ten_distinct_hosts() {
        let h = hosts();
        for i in 0..h.len() {
            assert!(!h[i].is_empty());
            for j in (i + 1)..h.len() {
                assert_ne!(h[i], h[j]);
            }
        }
    }
}
