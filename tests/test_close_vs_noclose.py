#!/usr/bin/env python3
"""Test echo response at 100KB WITHOUT Connection: close."""
import ssl, socket, os, sys, time

HOST = "localhost"
PORT = 8445
TOKEN = os.environ.get("OIDC_TOKEN", "")
if not TOKEN:
    print("ERROR: Set OIDC_TOKEN"); sys.exit(1)

# Test 1: 100KB with Connection: close
body = b"X" * (100 * 1024)
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
while True:
    chunk = sock.recv(65536)
    if not chunk:
        break
    buf += chunk
sock.close()
idx = buf.index(b"\r\n\r\n")
resp_body = buf[idx+4:]
print(f"WITH close:    sent={len(body)}, recv_body={len(resp_body)}, total_recv={len(buf)}")

# Test 2: 100KB WITHOUT Connection: close, use timeout to stop recv
body = b"Y" * (100 * 1024)
headers = (
    f"POST /data HTTP/1.1\r\n"
    f"Host: {HOST}\r\n"
    f"Content-Length: {len(body)}\r\n"
    f"Authorization: Bearer {TOKEN}\r\n"
    f"\r\n"
).encode()
raw2 = socket.create_connection((HOST, PORT), timeout=10)
sock2 = ctx.wrap_socket(raw2, server_hostname=HOST)
sock2.sendall(headers + body)
# Read with timeout
sock2.settimeout(5)
buf2 = b""
try:
    while True:
        chunk = sock2.recv(65536)
        if not chunk:
            break
        buf2 += chunk
except socket.timeout:
    pass
sock2.close()
if b"\r\n\r\n" in buf2:
    idx2 = buf2.index(b"\r\n\r\n")
    resp_body2 = buf2[idx2+4:]
    # Try to get Content-Length
    for line in buf2[:idx2].decode("ascii", errors="replace").split("\r\n"):
        if line.lower().startswith("content-length:"):
            print(f"  Content-Length: {line.split(':',1)[1].strip()}")
    print(f"WITHOUT close: sent={len(body)}, recv_body={len(resp_body2)}, total_recv={len(buf2)}")
else:
    print(f"WITHOUT close: no headers, total_recv={len(buf2)}")
