# Trusted Time

An SGX enclave has no clock of its own. Every time it reads comes from the
host, and a host that rolls its clock back can get expired credentials
accepted: quote freshness, RA-TLS certificate dates, JWT `exp`/`nbf`,
EncAuth vouchers, FIDO2 challenges, vault key expiry and time windows all
rest on that time.

enclave-os-mini therefore reads the time in exactly one place, checks the
host's answer against a sealed floor, a platform monitor and NTS servers
on the internet, and fails closed when it cannot.

The platform monitor is the `platform-monitoring` app, an instance of
[container-app-service-monitoring](https://github.com/Privasys/container-app-service-monitoring/blob/main/docs/platform-clock.md)
running its platform clock. It polls every enclave's core every 5
minutes and has the platform quarantine, at the gateways, an enclave
whose host clock is wrong, that has no trusted time, or that misses two
polls in a row. The enclave keeps running and its manager route stays
up, so the monitor can keep checking it; a clean poll releases it.

## The choke point

Every time read goes through `enclave/src/trustedtime`, reached through the
OCall vtable:

| Call | Returns |
|------|---------|
| `enclave_os_common::ocall::get_current_time()` | Trusted time, Unix seconds |
| `enclave_os_common::ocall::get_current_time_ms()` | Trusted time, Unix milliseconds |

An `Err` (`NO_TRUSTED_TIME`, `-62`) means there is no trusted time right
now. Every caller fails closed; none substitutes 0 (a 0 time makes every
expiry look far away):

- quote freshness on the RA-TLS server (`present` evidence), on peer
  links and in the egress RA-TLS exchange;
- EncAuth vouchers and the browser session relay;
- JWT `exp`/`nbf` (platform and app tokens), FIDO2 ceremonies and session
  tokens;
- vault key expiry, `TimeWindow`, approval and step-up freshness, audit
  stamps;
- the egress JWKS cache, the raft replay clock;
- the WASI `wall-clock` and `monotonic-clock`: the call **traps** (1 ms
  resolution; the monotonic clock is the same time in nanoseconds and
  never goes back);
- every rustls config that verifies a peer (egress, peer links) takes its
  clock from the choke point, never from the sysroot.

What the enclave issues itself (its own leaf certificates, the
`quote_time` it stamps) uses trusted time, or the frozen floor when there
is none: their validity is the peer's check. The RA-TLS server's own TLS
clock (session tickets, resumption) is the same issue time: serving TLS
is not a decision on trusted time, and while trusted time is failing
closed the enclave stays reachable, above all for the monitor's poll.
Only verification decisions fail closed.

`std::time::SystemTime::now()` would bypass all of this: the Teaclave
sysroot answers it with its own untrusted ocall. It is banned in enclave
code by `clippy.toml` (`disallowed-methods`; the host crate has its own
`clippy.toml`) and by a source check in CI. The host's clock is read only
by the choke point, through the `GetCurrentTimeMs` RPC.

## The algorithm

State, sealed with MRENCLAVE policy in the host KV store (`system` table):
`floor` (the highest confirmed time), `flagged` and its reason, and the
monitor config. `last_returned` stays in memory.

- **Reads never go back.** A read returns at least the previous read and
  at least the floor.
- **The floor only rises from a confirmed time**: a host time the monitor
  or NTS agreed with (within 10 s), or an NTS time. A host that jumps
  forward cannot push it past real time.
- **Boot:** restore the sealed floor (never below `MIN_TRUSTED_TIME`,
  2026-09-18T00:00:00Z, compiled in), then one NTS fetch before the first
  time-sensitive decision. A host that rolls the sealed state back only
  restores an older floor, which this fetch corrects.
- **Host behind the floor** (more than 1 s): an incident. It is reported
  to the monitor, which must answer with a signed receipt, then NTS is
  fetched and the enclave serves the NTS time **frozen** (never an offset:
  an offset would still move at the host's pace). No receipt: fail
  closed.
- **Flagged:** reads return the frozen time; NTS is fetched again every
  100 reads (the enclave cannot tell that a poll is late, so this bounds
  how stale the frozen time gets on reads the host drives). The flag
  clears when NTS confirms the host. A failed refetch fails closed.
- **No NTS quorum when one is needed** fails closed. The fetch is retried
  every 100 reads and on every signed monitor poll (after its signature
  is checked), so an idle enclave recovers as soon as NTS is back.
- **Blocked polls are the monitor's to catch:** a host that stops the
  monitor's polls gets its enclave quarantined after two missed polls, so
  reads between polls never reach NTS on their own.
- **Bounded raises:** a poll in sync (host and monitor agreeing, no NTS)
  raises the floor by at most one hour. A larger jump needs an NTS quorum
  confirming the host, so the monitor key and the host together cannot
  push the floor into the future.
- **No monitor configured:** incidents are only logged. NTS still decides.

What a poll finds (`host_clock_wrong`, `monitor_clock_wrong`, no NTS
quorum) is in the poll reply and is never sent as an incident: the
monitor polls again after every incident, which would loop. Incidents are
for what is found outside a poll: the host behind the floor, the boot
fetch (`nts_unreachable`, `host_clock_wrong`) and a failed refetch.
Only `host_behind_floor` waits for the receipt (and fails closed without
it); the others are sent on the next read, never inside a poll, and a
lost one is logged. Each condition is reported once, until
the host time is confirmed again.

Known limit: the enclave cannot measure how long it waited for an NTS
reply. A host can hold a reply for X seconds and roll its clock back by X
to match; the unseen lag is the tolerance plus the receive timeout (2 s).

The pure parts (state machine, NTS codecs, quorum, wire contracts) live in
`crates/enclave-os-clock`, which builds and tests on any host:

```bash
cargo test --manifest-path crates/enclave-os-clock/Cargo.toml
```

## NTS

NTS (RFC 8915) inside the enclave:

1. **NTS-KE** over TCP 4460 with rustls: TLS 1.3, ALPN `ntske/1`, the
   server certificate checked against the Mozilla roots (webpki-roots)
   **at the floor**, not at host time. When the floor is older than the
   chain (a fresh enclave, or one that was down for weeks), the chain is
   checked at its newest `notBefore` instead: a certificate that expired
   before the floor is still refused, and the server's time must not be
   earlier than the time the chain was checked at.
2. The client offers AEAD_AES_128_GCM_SIV (30) then AEAD_AES_SIV_CMAC_256
   (15) and uses whichever the server picks. Keys come from the TLS
   exporter (`EXPORTER-network-time-security`); for GCM-SIV the context
   carries id 15, as the deployed servers derive it.
3. **NTPv4** over the UDP ops with the Unique Identifier, NTS Cookie and
   Authenticator extension fields. A reply counts only if its
   Authenticator verifies, it echoes our Unique Identifier and our
   (random) transmit timestamp. The server's transmit timestamp is the
   time.

The AEADs are RustCrypto; the enclave build selects their portable
constant-time backends (`--cfg aes_force_soft --cfg polyval_force_soft`).

**Quorum:** two servers picked at random must agree within 2 s; otherwise
a third is asked and the closest agreeing pair wins. The servers of one
round are sampled together (all requests sent before any reply is read).
A failing server is replaced by the next one in the random order. No
agreeing pair: no quorum.

**Bounded cost:** at most three servers and two rounds per quorum. Each
NTS-KE connect, and each read or write on it, waits at most 2 s; each NTP
reply at most 2 s. Unreachable or silent servers cost a quorum about 2 s
each, well under 20 s in all.

**Pinned servers**, one per operator, compiled in (a change is a runtime
roll, never configuration):

| Host | Operator |
|------|----------|
| `nts.netnod.se` | Netnod, Sweden |
| `ptbtime1.ptb.de` | PTB, Germany |
| `nts.time.nl` | TimeNL (SIDN), Netherlands |
| `time.cloudflare.com` | Cloudflare, Europe |
| `ntp3.fau.de` | FAU Erlangen-Nuernberg, Germany |
| `ntp1.cam.ac.uk` | University of Cambridge, UK |
| `nts2.ntp.hr` | University of Zagreb FER, Croatia |
| `paris.time.system76.com` | System76, France |
| `ntp1.rdem-systems.com` | RDEM Systems, France |
| `nts.teambelgium.net` | Team Belgium, Belgium |

**Waiting without blocking the enclave.** In WASM builds, requests run as
tasks on the enclave's event loop (see `enclave_os_wasm::executor`). A
clock operation started by the clock's own routes (`POST /clock/poll`,
`PUT /clock/config`), at the top of their request where no lock is held,
does its NTS quorum and incident POST over sockets the host proxy drives
(`TcpConnect` / `UdpOpen` with the same timeouts, enforced by the proxy),
and each network wait suspends only that request: the enclave keeps
serving the others. Meanwhile another request's time read gets the state
as of the last operation: `NO_TRUSTED_TIME` if that was failing closed,
otherwise the frozen time (time pauses, never goes back); another clock
route waits its turn. A time read never suspends (it may come from under
any lock, and a request suspended while holding a lock would block the
next one that takes it, on the enclave's one thread), so an NTS fetch a
read starts (boot, refetch, incidents) still blocks, as do
all of them in builds without WASM.

## Monitor contracts

Keys are Ed25519, times are Unix milliseconds, base64 is base64url
without padding. Signed payloads are the exact UTF-8 bytes of their lines
joined with `\n`, no trailing newline. `monitor_key_id` is the first 16 hex
characters (lowercase) of `sha256(public key)`.

### `PUT /clock/config`

From management-service. Always the manager role: unlike the other
manager-only core routes, it is refused (403) when no OIDC is configured,
since it sets the key every poll and receipt is checked against. Sealed
with the floor.

```json
{ "enclave_id": "<mgmt enclave uuid>",
  "monitor_key": "<base64url 32-byte Ed25519 public key>",
  "monitor_key_id": "<first 16 hex of sha256(monitor_key)>",
  "incident_url": "https://<monitor host>/api/v1/clock/incidents",
  "config_version": 3 }
```

| Status | Body | When |
|--------|------|------|
| 200 | `{"enclave_id", "monitor_key_id", "config_version", "applied": true}` | Higher `config_version`: applied |
| 200 | same, `"applied": false` | Same `config_version` as the sealed one: no-op, config kept |
| 400 | `{"error": "..."}` | Invalid body, key, key id or URL |
| 403 | `{"error": "manager role required"}` | Bearer missing or not manager, or no OIDC configured |
| 409 | `{"error": "...", "config_version": <current>}` | Lower `config_version` |

The request needs a `Content-Length` (Go's `net/http` sets it for a byte
body); chunked bodies are not read.

### `POST /clock/poll`

From the monitor. No bearer: the signature is the authentication.

```json
{ "enclave_id": "...", "t_ms": 1789000000000, "seq": 42,
  "key_id": "...", "sig": "<base64url>" }
```

Signed bytes: `privasys-clock-floor/v1`, `enclave_id`, `t_ms`, `seq`.

On the poll, the enclave compares its host time `H` with `T`: within
10 s the floor rises to `H` (`in_sync`); otherwise NTS decides between
them (`monitor_clock_wrong`, or `host_clock_wrong` which freezes). A `T`
below the floor is ignored (`ignored_stale`).

Reply (authentic through the RA-TLS channel):

```json
{ "enclave_id": "...", "runtime": "mini", "host_time_ms": 0,
  "trusted_time_ms": 0, "floor_ms": 0, "flagged": false,
  "reason": "", "verdict": "in_sync|monitor_clock_wrong|host_clock_wrong|ignored_stale",
  "nts": { "time_ms": 0, "servers": [] },
  "config_key_id": "..." }
```

- `nts` describes the fetch this poll made; `{"time_ms": 0, "servers": []}`
  when it made none.
- While trusted time is failing closed, `reason` names the problem
  (`nts_unreachable`, `host_behind_floor`) and `trusted_time_ms` is 0.

| Status | Body | When |
|--------|------|------|
| 200 | the reply | |
| 400 | `{"error": "..."}` | Malformed body |
| 401 | `{"error": "..."}` | Wrong `enclave_id`, unknown `key_id`, bad signature |
| 409 | `{"error": "clock not configured"}` | No clock config yet |
| 503 | `{"error": "nts_unreachable", "detail", "host_time_ms", "floor_ms"}` | Host and monitor disagree and no NTS quorum |

### Incident

`POST {incident_url}` over TLS 1.3 with ALPN `privasys-ratls/1`, so the
platform gateway splices the connection through to the monitor enclave
(its runtime refuses plaintext API calls on the gateway's terminating
leg). The monitor's certificate is an RA-TLS certificate, not a web PKI
one, and is not checked: the report carries nothing secret, and the
receipt, which only the pinned monitor key can sign, is the
authentication. A party in the middle can only withhold the receipt,
which the host can do anyway. The connect, and each read or write, waits
at most 5 s.

```json
{ "enclave_id": "...", "reason": "host_behind_floor|host_clock_wrong|monitor_clock_wrong|nts_unreachable",
  "host_time_ms": 0, "floor_ms": 0, "nts_time_ms": 0, "nonce": "<base64url 32 bytes>" }
```

Receipt: `{"incident_id", "nonce", "key_id", "sig"}`, signed bytes
`privasys-clock-receipt/v1`, `enclave_id`, `nonce` (the base64url string
as sent), `incident_id`. The enclave is single-threaded: the monitor must
answer with the receipt before it polls the enclave back, not after.

## UDP host ops

NTP needs UDP, which crosses the host like every other byte. The RPC
channel has generic datagram ops (handles are distinct from TCP ones):

| Method | Id | Request payload | Response |
|--------|----|-----------------|----------|
| `NetUdpBind` | `0x0110` | `[u16 port][bind address]` (empty = `0.0.0.0`, port 0 = ephemeral) | fd |
| `NetUdpSendTo` | `0x0111` | `[i32 fd][u16 port][u16 host_len][host][datagram]` | bytes sent |
| `NetUdpRecvFrom` | `0x0112` | `[i32 fd][u32 max_len][u32 timeout_ms]` | `[u16 addr_len][peer "ip:port"][datagram]`; `-11` on timeout |
| `NetUdpClose` | `0x0113` | `[i32 fd]` | none |

The host resolves hostnames to the socket's address family and caps a
receive at 10 s. In the enclave they are `ocall::net_udp_*`, also on the
OCall vtable for module crates.

Alongside, `NetTcpConnectTimeout` (`0x0106`, payload
`[u16 port][u32 timeout_ms][host]`, response fd) is a TCP connect whose
connect, and every later recv or send, waits at most `timeout_ms` (capped
at 30 s): it bounds the NTS-KE legs and the incident POST.

The suspending path uses the data channel instead (`common::channel`):
`TcpConnect` with a `\n<ms>` suffix is a proxy-owned TCP connection
whose connect and every quiet period (no byte either way) the proxy bounds
at that many milliseconds; `UdpOpen` (`0x08`, same payload) is a UDP socket
connected to its one peer, each `TcpData` on it one datagram, closed by the
proxy after the same quiet period, which the enclave reads as the
receive timeout.
