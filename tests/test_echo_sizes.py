#!/usr/bin/env python3
"""Test echo responses of varying sizes to find the cutoff."""
import ssl, socket, os, sys

HOST = "localhost"
PORT = 8445
TOKEN = os.environ.get("OIDC_TOKEN", "")
if not TOKEN:
    print("ERROR: Set OIDC_TOKEN"); sys.exit(1)

def test_echo(size_kb):
    body = b"X" * (size_kb * 1024)
    headers = (
        f"POST /data HTTP/1.1\r\n"
        f"Host: {HOST}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Authorization: Bearer {TOKEN}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection((HOST, PORT), timeout=10)
    sock = ctx.wrap_socket(raw, server_hostname=HOST)
    sock.sendall(headers + body)
    buf = b""
    try:
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            buf += chunk
    except Exception as e:
        print(f"  {size_kb}KB: recv error: {e}, got {len(buf)} bytes")
        sock.close()
        return
    sock.close()
    # Parse response
    if b"\r\n\r\n" not in buf:
        print(f"  {size_kb}KB: no headers in {len(buf)} bytes")
        return
    idx = buf.index(b"\r\n\r\n")
    resp_body = buf[idx+4:]
    print(f"  {size_kb}KB: sent={len(body)}, response_body={len(resp_body)}, match={len(resp_body)==len(body)}")

for kb in [100, 500, 800, 900, 950, 1000, 1024, 1100, 1500]:
    test_echo(kb)
