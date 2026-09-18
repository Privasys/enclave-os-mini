// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! NTS client (RFC 8915): NTS-KE over TLS 1.3 inside the enclave, then
//! authenticated NTPv4 over the host's UDP sockets.
//!
//! In a request task the sockets are ones the host proxy drives, and every
//! network wait suspends the task instead of the enclave (see [`io`]); the
//! proxy enforces the same timeouts the host RPC sockets take. Elsewhere
//! (start-up, the event loop, inside a guest call) the host's RPC sockets
//! block, as before.
//!
//! Every byte crosses the host. NTS-KE is TLS terminated here, with the
//! server certificate checked against the Mozilla roots (webpki-roots) at
//! the enclave's floor time, never at the host's time (that time is what is
//! in question). The NTP packets are authenticated with keys exported from
//! that TLS session, so the host can drop or delay them but cannot forge
//! or alter them.
//!
//! The host's delay is the one thing SGX cannot measure: the enclave has no
//! clock to time a round trip with. A host can hold a reply for X seconds
//! and roll its clock back by X to match; the unseen lag is bounded by the
//! tolerance plus the receive timeout.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::string::{String, ToString};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use std::vec::Vec;

use ring::rand::{SecureRandom, SystemRandom};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::time_provider::TimeProvider;
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, Error, RootCertStore, SignatureScheme};

use enclave_os_clock::aead::{NtsAead, MAX_NONCE_LEN};
use enclave_os_clock::ntske::{self, EXPORTER_LABEL, KE_PORT, NTP_PORT};
use enclave_os_clock::quorum::{self, NtsSample};
use enclave_os_clock::{ntp, servers, ClockError, TOLERANCE_MS};

use super::io;
use crate::ocall;

/// How long one NTP reply is waited for.
const RECV_TIMEOUT_MS: u32 = 2_000;

/// How long an NTS-KE connect, and each read or write on it, may wait.
/// With at most three servers per quorum this keeps a quorum against
/// unreachable or silent servers well under 20 s.
const KE_TIMEOUT_MS: u32 = 2_000;

/// How long the incident POST, and each read or write on it, may wait:
/// the bound on waiting for the monitor's receipt.
const INCIDENT_TIMEOUT_MS: u32 = 5_000;

/// ALPN that makes the platform gateway splice the connection through to
/// the monitor enclave rather than terminate TLS itself.
const RATLS_ALPN: &[u8] = b"privasys-ratls/1";

/// Datagrams read per request before giving up on a valid reply (anything
/// that fails authentication is dropped: it may be the host's).
const MAX_DATAGRAMS_PER_REPLY: usize = 4;

/// One NTS-KE result: the negotiated AEAD, its two keys and the cookies
/// to spend.
struct Session {
    aead: NtsAead,
    c2s: Vec<u8>,
    s2c: Vec<u8>,
    cookies: Vec<Vec<u8>>,
    ntp_host: String,
    ntp_port: u16,
    /// The time the certificate chain was checked at. The server's time
    /// cannot be earlier: no certificate is issued in the future.
    checked_at_ms: i64,
}

/// An NTP request waiting for its reply.
struct InFlight {
    sock: Udp,
    uid: [u8; ntp::UID_LEN],
    xmt: [u8; 8],
    aead: NtsAead,
    s2c: Vec<u8>,
    checked_at_ms: i64,
}

/// An NTS quorum over the pinned servers, checking certificates at
/// `floor_ms`. In a request task its network waits suspend the task (see
/// [`io`]); elsewhere they block.
pub fn quorum(floor_ms: i64) -> Result<NtsSample, ClockError> {
    let hosts = servers::hosts();
    let rng = SystemRandom::new();
    let suspend = io::can_suspend();
    let mut sessions: BTreeMap<String, Session> = BTreeMap::new();
    quorum::run(
        &hosts,
        || {
            let mut b = [0u8; 4];
            let _ = rng.fill(&mut b);
            u32::from_le_bytes(b)
        },
        |set| io::run(suspend, sample_round(set, &mut sessions, floor_ms, &rng, suspend)),
    )
}

/// Sample every host of `set` in one round: key exchanges first (only for
/// hosts without an unspent cookie), then every NTP request, then every
/// reply, so the samples are close together in time.
async fn sample_round(
    set: &[&str],
    sessions: &mut BTreeMap<String, Session>,
    floor_ms: i64,
    rng: &SystemRandom,
    suspend: bool,
) -> Vec<Result<i64, String>> {
    let mut out: Vec<Result<i64, String>> = set.iter().map(|_| Err(String::new())).collect();

    for (i, host) in set.iter().enumerate() {
        if sessions.get(*host).map_or(false, |s| !s.cookies.is_empty()) {
            continue;
        }
        match key_exchange(host, floor_ms, suspend).await {
            Ok(s) => {
                sessions.insert(host.to_string(), s);
            }
            Err(e) => {
                sessions.remove(*host);
                out[i] = Err(format!("nts-ke: {e}"));
            }
        }
    }

    let mut inflight: Vec<Option<InFlight>> = Vec::with_capacity(set.len());
    for (i, host) in set.iter().enumerate() {
        let f = match sessions.get_mut(*host) {
            Some(s) if !s.cookies.is_empty() => match send_request(s, rng, suspend) {
                Ok(f) => Some(f),
                Err(e) => {
                    out[i] = Err(format!("ntp send: {e}"));
                    None
                }
            },
            _ => None,
        };
        inflight.push(f);
    }

    for (i, f) in inflight.into_iter().enumerate() {
        if let Some(f) = f {
            out[i] = receive(&f).await;
            f.sock.close();
        }
    }
    out
}

fn random<const N: usize>(rng: &SystemRandom) -> Result<[u8; N], String> {
    let mut b = [0u8; N];
    rng.fill(&mut b).map_err(|_| "rng failure".to_string())?;
    Ok(b)
}

fn send_request(s: &mut Session, rng: &SystemRandom, suspend: bool) -> Result<InFlight, String> {
    let cookie = s.cookies.pop().ok_or("no cookie left")?;
    let uid: [u8; ntp::UID_LEN] = random(rng)?;
    let xmt: [u8; 8] = random(rng)?;
    let nonce: [u8; MAX_NONCE_LEN] = random(rng)?;
    let pkt = ntp::build_request(s.aead, &s.c2s, &cookie, &uid, &xmt, &nonce[..s.aead.nonce_len()])
        .ok_or("request encryption failed")?;
    let sock = Udp::open(&s.ntp_host, s.ntp_port, suspend)?;
    if let Err(e) = sock.send(&pkt) {
        sock.close();
        return Err(e);
    }
    Ok(InFlight { sock, uid, xmt, aead: s.aead, s2c: s.s2c.clone(), checked_at_ms: s.checked_at_ms })
}

async fn receive(f: &InFlight) -> Result<i64, String> {
    let mut last = String::from("no reply");
    for _ in 0..MAX_DATAGRAMS_PER_REPLY {
        match f.sock.recv().await? {
            Some(d) => match ntp::parse_response(&d, f.aead, &f.s2c, &f.uid, &f.xmt) {
                Ok(t) if t < f.checked_at_ms.saturating_sub(TOLERANCE_MS) => {
                    return Err("server time is before its own certificate".to_string());
                }
                Ok(t) => return Ok(t),
                Err(e) => last = e.to_string(),
            },
            None => return Err(format!("no valid reply ({last})")),
        }
    }
    Err(format!("no valid reply ({last})"))
}

// ---------------------------------------------------------------------------
//  NTS-KE
// ---------------------------------------------------------------------------

async fn key_exchange(host: &str, floor_ms: i64, suspend: bool) -> Result<Session, String> {
    let mut tcp = Tcp::connect(host, KE_PORT, KE_TIMEOUT_MS, suspend)?;
    let r = key_exchange_on(&mut tcp, host, floor_ms).await;
    tcp.close();
    r
}

async fn key_exchange_on(tcp: &mut Tcp, host: &str, floor_ms: i64) -> Result<Session, String> {
    let checked_at = Arc::new(AtomicI64::new(floor_ms));
    let config = client_config(floor_ms, Some(ntske::ALPN), checked_at.clone())?;
    let name = ServerName::try_from(host.to_string()).map_err(|_| "invalid server name".to_string())?;
    let mut conn = ClientConnection::new(Arc::new(config), name).map_err(|e| format!("tls init: {e}"))?;
    handshake(tcp, &mut conn).await?;
    if conn.alpn_protocol() != Some(ntske::ALPN) {
        return Err("server did not negotiate ntske/1".to_string());
    }

    conn.writer()
        .write_all(&ntske::build_request())
        .map_err(|e| format!("write: {e}"))?;
    flush(tcp, &mut conn)?;

    let mut buf = Vec::new();
    let resp = loop {
        if let Some(r) = ntske::parse_response(&buf).map_err(|e| e.to_string())? {
            break r;
        }
        if read_plaintext(tcp, &mut conn, &mut buf, ntske::MAX_RESPONSE).await? == 0 {
            return Err("connection closed before end of message".to_string());
        }
    };

    let aead = resp.aead;
    let c2s = conn
        .export_keying_material(vec![0u8; aead.key_len()], EXPORTER_LABEL, Some(&ntske::exporter_context(aead, false)))
        .map_err(|e| format!("exporter: {e}"))?;
    let s2c = conn
        .export_keying_material(vec![0u8; aead.key_len()], EXPORTER_LABEL, Some(&ntske::exporter_context(aead, true)))
        .map_err(|e| format!("exporter: {e}"))?;
    conn.send_close_notify();
    let _ = flush(tcp, &mut conn);

    Ok(Session {
        aead,
        c2s,
        s2c,
        cookies: resp.cookies,
        ntp_host: resp.server.unwrap_or_else(|| host.to_string()),
        ntp_port: resp.port.unwrap_or(NTP_PORT),
        checked_at_ms: checked_at.load(Ordering::Relaxed),
    })
}

// ---------------------------------------------------------------------------
//  TLS at the floor time
// ---------------------------------------------------------------------------

fn mozilla_roots() -> Arc<RootCertStore> {
    static ROOTS: OnceLock<Arc<RootCertStore>> = OnceLock::new();
    ROOTS
        .get_or_init(|| {
            let mut store = RootCertStore::empty();
            store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            Arc::new(store)
        })
        .clone()
}

/// A TLS 1.3 client config whose clock is `at_ms` and whose certificate
/// check runs at the floor (see [`FloorVerifier`]).
fn client_config(at_ms: i64, alpn: Option<&[u8]>, checked_at: Arc<AtomicI64>) -> Result<ClientConfig, String> {
    let provider = Arc::new(default_provider());
    let inner = WebPkiServerVerifier::builder_with_provider(mozilla_roots(), provider.clone())
        .build()
        .map_err(|e| format!("verifier: {e}"))?;
    let mut config = ClientConfig::builder_with_details(provider, Arc::new(FixedTime(at_ms)))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| format!("tls config: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(FloorVerifier { inner, floor_ms: at_ms, checked_at }))
        .with_no_client_auth();
    if let Some(p) = alpn {
        config.alpn_protocols = vec![p.to_vec()];
    }
    Ok(config)
}

/// A fixed clock for rustls, so nothing in the TLS stack reads the host's.
#[derive(Debug)]
struct FixedTime(i64);

impl TimeProvider for FixedTime {
    fn current_time(&self) -> Option<UnixTime> {
        Some(UnixTime::since_unix_epoch(Duration::from_millis(self.0.max(0) as u64)))
    }
}

/// WebPKI chain validation against the Mozilla roots, at the floor.
///
/// The floor is a verified time, but it can be old (a fresh enclave starts
/// at its build date; one that was down for weeks restores an old floor),
/// and a certificate issued after it would look "not yet valid". So the
/// chain is checked at the later of the floor and the newest `notBefore`
/// in the chain: a certificate that expired before the floor is still
/// refused, and the time the server then reports must not be earlier than
/// the time the chain was checked at (no certificate is issued in the
/// future).
#[derive(Debug)]
struct FloorVerifier {
    inner: Arc<WebPkiServerVerifier>,
    floor_ms: i64,
    checked_at: Arc<AtomicI64>,
}

impl ServerCertVerifier for FloorVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let mut at_ms = self.floor_ms;
        for der in core::iter::once(end_entity).chain(intermediates.iter()) {
            if let Ok((_, cert)) = x509_parser::parse_x509_certificate(der.as_ref()) {
                at_ms = at_ms.max(cert.validity().not_before.timestamp().saturating_mul(1_000));
            }
        }
        self.checked_at.store(at_ms, Ordering::Relaxed);
        let at = UnixTime::since_unix_epoch(Duration::from_millis(at_ms.max(0) as u64));
        self.inner.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, at)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

// ---------------------------------------------------------------------------
//  TLS pump over a TCP socket
// ---------------------------------------------------------------------------

fn flush(tcp: &mut Tcp, conn: &mut ClientConnection) -> Result<(), String> {
    while conn.wants_write() {
        let mut out = Vec::new();
        conn.write_tls(&mut out).map_err(|e| format!("write_tls: {e}"))?;
        tcp.send_all(&out)?;
    }
    Ok(())
}

/// Read one chunk from the network into the TLS session. Returns the number
/// of network bytes read (0 at end of stream).
async fn pump_in(tcp: &mut Tcp, conn: &mut ClientConnection) -> Result<usize, String> {
    let mut net = vec![0u8; 16 * 1024];
    let n = tcp.recv(&mut net).await?;
    let mut cursor = std::io::Cursor::new(&net[..n]);
    while (cursor.position() as usize) < n {
        conn.read_tls(&mut cursor).map_err(|e| format!("read_tls: {e}"))?;
        conn.process_new_packets().map_err(|e| format!("tls: {e}"))?;
    }
    Ok(n)
}

async fn handshake(tcp: &mut Tcp, conn: &mut ClientConnection) -> Result<(), String> {
    loop {
        flush(tcp, conn)?;
        if !conn.is_handshaking() {
            return Ok(());
        }
        if pump_in(tcp, conn).await? == 0 {
            return Err("connection closed during the handshake".to_string());
        }
    }
}

/// Read network data and append the decrypted bytes to `out`. Returns the
/// number of network bytes read (0 at end of stream).
async fn read_plaintext(tcp: &mut Tcp, conn: &mut ClientConnection, out: &mut Vec<u8>, cap: usize) -> Result<usize, String> {
    let n = pump_in(tcp, conn).await?;
    let mut tmp = [0u8; 4096];
    loop {
        match conn.reader().read(&mut tmp) {
            Ok(0) => break,
            Ok(m) => {
                out.extend_from_slice(&tmp[..m]);
                if out.len() > cap {
                    return Err("response too large".to_string());
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(format!("read: {e}")),
        }
    }
    Ok(n)
}

// ---------------------------------------------------------------------------
//  Incident POST to the monitor
// ---------------------------------------------------------------------------

/// POST an incident (JSON) to the monitor and return the body of its 2xx
/// reply.
///
/// The monitor is an enclave behind the platform gateway, and its runtime
/// refuses plaintext API calls on the gateway's terminating leg. ALPN
/// `privasys-ratls/1` makes the gateway splice the connection through to
/// the monitor enclave instead, so the enclave talks TLS to the monitor
/// itself.
///
/// The monitor's certificate is an RA-TLS certificate, not a web PKI one,
/// and it is not checked here: the report carries nothing secret, and what
/// the enclave needs back is the receipt, which only the pinned monitor
/// key can sign (the caller verifies it). Whoever sits in the middle can
/// only withhold the receipt, which the host can do anyway. Each connect,
/// read and write waits at most [`INCIDENT_TIMEOUT_MS`], which bounds the
/// wait for the receipt.
pub fn post_to_monitor(url: &str, body: &[u8], at_ms: i64) -> Result<Vec<u8>, String> {
    let suspend = io::can_suspend();
    io::run(suspend, post_to_monitor_on(url, body, at_ms, suspend))
}

async fn post_to_monitor_on(url: &str, body: &[u8], at_ms: i64, suspend: bool) -> Result<Vec<u8>, String> {
    let rest = url.strip_prefix("https://").ok_or("incident_url is not https")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().map_err(|_| "bad port in incident_url".to_string())?),
        None => (authority, 443),
    };

    let mut tcp = Tcp::connect(host, port, INCIDENT_TIMEOUT_MS, suspend)?;
    let r = incident_exchange(&mut tcp, host, authority, path, body, at_ms).await;
    tcp.close();
    r
}

/// The TLS session and HTTP exchange of [`post_to_monitor`].
async fn incident_exchange(
    tcp: &mut Tcp,
    host: &str,
    authority: &str,
    path: &str,
    body: &[u8],
    at_ms: i64,
) -> Result<Vec<u8>, String> {
    const MAX_REPLY: usize = 64 * 1024;
    let provider = Arc::new(default_provider());
    // The TLS stack gets the frozen floor as its clock, never the host's.
    let mut config = ClientConfig::builder_with_details(provider.clone(), Arc::new(FixedTime(at_ms)))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| format!("tls config: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(ReceiptAuthenticates(provider)))
        .with_no_client_auth();
    config.alpn_protocols = vec![RATLS_ALPN.to_vec()];
    config.resumption = rustls::client::Resumption::disabled();
    let name = ServerName::try_from(host.to_string()).map_err(|_| "invalid server name".to_string())?;
    let mut conn = ClientConnection::new(Arc::new(config), name).map_err(|e| format!("tls init: {e}"))?;
    handshake(tcp, &mut conn).await?;
    let mut req = format!(
        "POST {path} HTTP/1.1\r\nHost: {authority}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    req.extend_from_slice(body);
    conn.writer().write_all(&req).map_err(|e| format!("write: {e}"))?;
    flush(tcp, &mut conn)?;
    let mut raw = Vec::new();
    loop {
        if let Some(body) = parse_http_reply(&raw, false)? {
            return Ok(body);
        }
        if read_plaintext(tcp, &mut conn, &mut raw, MAX_REPLY).await? == 0 {
            return parse_http_reply(&raw, true)?.ok_or_else(|| "incomplete HTTP reply".to_string());
        }
    }
}

/// Accepts the monitor's certificate without a trust decision: the signed
/// receipt is the authentication (see [`post_to_monitor`]). The handshake
/// signature is still checked against the presented key, so the TLS
/// session itself is sound.
#[derive(Debug)]
struct ReceiptAuthenticates(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for ReceiptAuthenticates {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Parse an HTTP/1.1 reply. `Ok(None)` while it is incomplete; `eof` says
/// the peer closed, which completes a body without a length.
fn parse_http_reply(raw: &[u8], eof: bool) -> Result<Option<Vec<u8>>, String> {
    let Some(split) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
        return Ok(None);
    };
    let head = core::str::from_utf8(&raw[..split]).map_err(|_| "non-UTF-8 HTTP head".to_string())?;
    let mut lines = head.split("\r\n");
    let status: u16 = lines
        .next()
        .and_then(|l| l.split(' ').nth(1))
        .and_then(|s| s.parse().ok())
        .ok_or("bad HTTP status line")?;
    let mut chunked = false;
    let mut length: Option<usize> = None;
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            if k.trim().eq_ignore_ascii_case("transfer-encoding") && v.to_ascii_lowercase().contains("chunked") {
                chunked = true;
            } else if k.trim().eq_ignore_ascii_case("content-length") {
                length = v.trim().parse().ok();
            }
        }
    }
    let rest = &raw[split + 4..];
    let body = if chunked {
        let mut out = Vec::new();
        let mut p = rest;
        loop {
            let Some(eol) = p.windows(2).position(|w| w == b"\r\n") else {
                return Ok(None);
            };
            let size_str = core::str::from_utf8(&p[..eol]).map_err(|_| "bad chunk size".to_string())?;
            let size = usize::from_str_radix(size_str.split(';').next().unwrap_or("").trim(), 16)
                .map_err(|_| "bad chunk size".to_string())?;
            p = &p[eol + 2..];
            if size == 0 {
                break;
            }
            if p.len() < size + 2 {
                return Ok(None);
            }
            out.extend_from_slice(&p[..size]);
            p = &p[size + 2..];
        }
        out
    } else {
        match length {
            Some(n) if n <= rest.len() => rest[..n].to_vec(),
            Some(_) => return Ok(None),
            None if eof => rest.to_vec(),
            None => return Ok(None),
        }
    };
    if !(200..300).contains(&status) {
        return Err(format!("monitor answered HTTP {status}"));
    }
    Ok(Some(body))
}

// ---------------------------------------------------------------------------
//  Sockets
// ---------------------------------------------------------------------------

/// A TCP socket: the host's (blocking RPC) or one the host proxy drives
/// (its reads suspend the request task, see [`io`]).
enum Tcp {
    Rpc(i32),
    #[cfg(feature = "wasm")]
    Chan(enclave_os_egress::netchan::NetConn),
}

impl Tcp {
    /// Connect, with `timeout_ms` bounding the connect and each wait after.
    fn connect(host: &str, port: u16, timeout_ms: u32, suspend: bool) -> Result<Self, String> {
        #[cfg(feature = "wasm")]
        if suspend {
            return enclave_os_egress::netchan::NetConn::connect_timeout(host, port, timeout_ms)
                .map(Tcp::Chan)
                .map_err(|e| format!("connect {host}:{port}: {e}"));
        }
        let _ = suspend;
        ocall::net_tcp_connect_timeout(host, port, timeout_ms)
            .map(Tcp::Rpc)
            .map_err(|e| format!("connect {host}:{port}: {e}"))
    }

    fn send_all(&mut self, data: &[u8]) -> Result<(), String> {
        match self {
            Tcp::Rpc(fd) => {
                let mut off = 0;
                while off < data.len() {
                    let n = ocall::net_send(*fd, &data[off..]).map_err(|e| format!("send: {e}"))?;
                    if n == 0 {
                        return Err("send: connection closed".to_string());
                    }
                    off += n;
                }
                Ok(())
            }
            #[cfg(feature = "wasm")]
            Tcp::Chan(c) => c.send(data).map_err(|e| format!("send: {e}")),
        }
    }

    /// Read some bytes; 0 at the end of the stream (or the timeout, for a
    /// proxy socket).
    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, String> {
        match self {
            Tcp::Rpc(fd) => ocall::net_recv(*fd, buf).map_err(|e| format!("recv: {e}")),
            #[cfg(feature = "wasm")]
            Tcp::Chan(c) => c.recv(buf).await.map_err(|e| format!("recv: {e}")),
        }
    }

    fn close(self) {
        match self {
            Tcp::Rpc(fd) => ocall::net_close(fd),
            #[cfg(feature = "wasm")]
            Tcp::Chan(c) => drop(c),
        }
    }
}

/// A UDP socket to one NTP server: the host's (blocking RPC) or one the
/// host proxy drives.
enum Udp {
    Rpc { fd: i32, host: String, port: u16 },
    #[cfg(feature = "wasm")]
    Chan(enclave_os_egress::netchan::UdpConn),
}

impl Udp {
    fn open(host: &str, port: u16, suspend: bool) -> Result<Self, String> {
        #[cfg(feature = "wasm")]
        if suspend {
            // The proxy closes the socket after RECV_TIMEOUT_MS without a
            // datagram, which `recv` reports as a timeout.
            return enclave_os_egress::netchan::UdpConn::open(host, port, RECV_TIMEOUT_MS)
                .map(Udp::Chan)
                .map_err(|e| format!("udp open: {e}"));
        }
        let _ = suspend;
        let fd = ocall::net_udp_bind("", 0).map_err(|e| format!("udp bind: {e}"))?;
        Ok(Udp::Rpc { fd, host: host.to_string(), port })
    }

    fn send(&self, pkt: &[u8]) -> Result<(), String> {
        match self {
            Udp::Rpc { fd, host, port } => ocall::net_udp_send_to(*fd, host, *port, pkt)
                .map(|_| ())
                .map_err(|e| format!("udp send to {host}:{port}: {e}")),
            #[cfg(feature = "wasm")]
            Udp::Chan(c) => c.send(pkt).map_err(|e| format!("udp send: {e}")),
        }
    }

    /// The next datagram, `None` after [`RECV_TIMEOUT_MS`] without one.
    async fn recv(&self) -> Result<Option<Vec<u8>>, String> {
        match self {
            Udp::Rpc { fd, .. } => match ocall::net_udp_recv_from(*fd, 2048, RECV_TIMEOUT_MS) {
                Ok((d, _peer)) => Ok(Some(d)),
                Err(-11) => Ok(None),
                Err(e) => Err(format!("udp recv: {e}")),
            },
            #[cfg(feature = "wasm")]
            Udp::Chan(c) => Ok(c.recv().await.ok()),
        }
    }

    fn close(self) {
        match self {
            Udp::Rpc { fd, .. } => ocall::net_udp_close(fd),
            #[cfg(feature = "wasm")]
            Udp::Chan(c) => drop(c),
        }
    }
}
