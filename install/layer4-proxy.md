# Layer-4 TCP Proxy Setup

The enclave terminates TLS internally — the host-side TCP proxy
(`0.0.0.0:8443`) accepts **raw TCP** and forwards encrypted bytes into
the SGX enclave via the SPSC data channel.  A front-end load balancer
must therefore operate at **Layer 4 (TCP passthrough)** so the TLS
handshake reaches the enclave untouched.

> **Do NOT terminate TLS at the load balancer.**  The entire security
> model relies on TLS termination happening inside the enclave.  The
> load balancer sees only opaque ciphertext.

---

## Architecture

```
Client ──TLS──▶ Load Balancer (L4) ──TCP──▶ Host TCP Proxy (:8443)
                                                │
                                          SPSC data channel
                                                │
                                          SGX Enclave (TLS termination)
```

The load balancer can optionally inspect the **TLS SNI** (Server Name
Indication) to route traffic to different enclave instances — SNI is
sent in cleartext during the ClientHello so it is visible at L4.

---

## Option A — Caddy (with layer4 module)

Caddy does not ship with Layer 4 support out of the box.  You need a
custom build with the **caddy-l4** module:

### Build Caddy with L4

```bash
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
xcaddy build --with github.com/mholt/caddy-l4
```

### Caddyfile (JSON — caddy-l4 uses the JSON config)

Create `caddy.json`:

```json
{
  "apps": {
    "layer4": {
      "servers": {
        "enclave-proxy": {
          "listen": ["0.0.0.0:443"],
          "routes": [
            {
              "match": [
                {
                  "tls": {}
                }
              ],
              "handle": [
                {
                  "handler": "proxy",
                  "upstreams": [
                    {
                      "dial": ["127.0.0.1:8443"]
                    }
                  ]
                }
              ]
            }
          ]
        }
      }
    }
  }
}
```

### SNI-based routing (multiple enclaves)

```json
{
  "apps": {
    "layer4": {
      "servers": {
        "enclave-proxy": {
          "listen": ["0.0.0.0:443"],
          "routes": [
            {
              "match": [
                {
                  "tls": {
                    "sni": ["app1.example.com"]
                  }
                }
              ],
              "handle": [
                {
                  "handler": "proxy",
                  "upstreams": [
                    {
                      "dial": ["10.0.0.10:8443"]
                    }
                  ]
                }
              ]
            },
            {
              "match": [
                {
                  "tls": {
                    "sni": ["app2.example.com"]
                  }
                }
              ],
              "handle": [
                {
                  "handler": "proxy",
                  "upstreams": [
                    {
                      "dial": ["10.0.0.11:8443"]
                    }
                  ]
                }
              ]
            }
          ]
        }
      }
    }
  }
}
```

### Run

```bash
caddy run --config caddy.json
```

---

## Option B — HAProxy

HAProxy has native TCP (mode `tcp`) support with no plugins required.

### Install

```bash
# Debian / Ubuntu
sudo apt-get install haproxy

# RHEL / Fedora
sudo dnf install haproxy
```

### Configuration — `/etc/haproxy/haproxy.cfg`

#### Basic (single enclave)

```haproxy
global
    log         /dev/log local0
    maxconn     4096
    daemon

defaults
    log         global
    mode        tcp
    option      tcplog
    timeout connect  5s
    timeout client  60s
    timeout server  60s

frontend enclave_in
    bind *:443
    default_backend enclave_backend

backend enclave_backend
    server enclave1 127.0.0.1:8443 check
```

#### SNI-based routing (multiple enclaves)

```haproxy
global
    log         /dev/log local0
    maxconn     4096
    daemon

defaults
    log         global
    mode        tcp
    option      tcplog
    timeout connect  5s
    timeout client  60s
    timeout server  60s

frontend enclave_in
    bind *:443

    # Inspect the TLS ClientHello to extract the SNI hostname.
    # tcp-request inspect-delay gives HAProxy time to read the SNI
    # before routing.
    tcp-request inspect-delay 5s
    tcp-request content accept if { req_ssl_hello_type 1 }

    # Route by SNI
    use_backend enclave_app1 if { req_ssl_sni -i app1.example.com }
    use_backend enclave_app2 if { req_ssl_sni -i app2.example.com }

    # Fallback
    default_backend enclave_default

backend enclave_app1
    server enc1 10.0.0.10:8443 check

backend enclave_app2
    server enc2 10.0.0.11:8443 check

backend enclave_default
    server enc0 127.0.0.1:8443 check
```

### Health check (optional)

HAProxy's `check` directive sends a TCP connect probe by default.
The enclave's TCP proxy will accept and then close (no TLS handshake),
which counts as a passing health check.

For a deeper check you can use an `httpchk` on a separate non-TLS
health port if you add one later, or rely on the TCP check.

### Run

```bash
sudo systemctl enable --now haproxy

# Or manually:
haproxy -f /etc/haproxy/haproxy.cfg -db
```

---

## Verify

From any client machine, confirm the TLS handshake reaches the enclave:

```bash
# Direct (bypassing the load balancer)
openssl s_client -connect 127.0.0.1:8443 -servername app1.example.com </dev/null 2>&1 | head -20

# Via the load balancer
openssl s_client -connect lb.example.com:443 -servername app1.example.com </dev/null 2>&1 | head -20
```

Both should show the **same** RA-TLS certificate issued by the enclave's
internal CA — proof that TLS termination is happening inside SGX, not at
the load balancer.

---

## Notes

| Concern | Detail |
|---------|--------|
| **PROXY protocol** | Not required. The enclave receives `peer_addr` via the host TCP proxy's `TcpNew` message. If you enable PROXY protocol on the LB you would need to handle it in the host TCP proxy. |
| **Connection limits** | The enclave TCP proxy accepts up to 16 connections per poll cycle. For high-traffic deployments, tune `maxconn` accordingly. |
| **Timeouts** | Set LB timeouts ≥ the enclave's TLS session timeout. 60 s is a safe default. |
| **Keepalive** | The enclave supports multiple request/response frames per TLS connection. Avoid setting idle timeouts too low. |
| **TLS version** | The enclave enforces TLSv1.3 (`AES_256_GCM_SHA384`). Clients must support TLS 1.3. |
