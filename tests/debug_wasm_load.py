#!/usr/bin/env python3
"""Minimal debug test for wasm_load over HTTP/1.1."""
import ssl, socket, json, os, sys

HOST = "localhost"
PORT = 8445
TOKEN = os.environ.get("OIDC_TOKEN", "")

if not TOKEN:
    print("ERROR: Set OIDC_TOKEN")
    sys.exit(1)

with open("/home/ubuntu/projects/wasm_example.cwasm", "rb") as f:
    cwasm = f.read()

payload = json.dumps({
    "wasm_load": {
        "name": "example",
        "bytes": list(cwasm),
        "permissions": {"http_hosts": ["*"], "kv_namespaces": ["default"]}
    }
}).encode()

print(f"payload size: {len(payload)}")

headers = (
    f"POST /data HTTP/1.1\r\n"
    f"Host: {HOST}\r\n"
    f"Content-Length: {len(payload)}\r\n"
    f"Content-Type: application/json\r\n"
    f"Authorization: Bearer {TOKEN}\r\n"
    f"Connection: close\r\n"
    f"\r\n"
)
header_bytes = headers.encode()
print(f"header size: {len(header_bytes)}")
print(f"Content-Length value: {len(payload)}")

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
raw = socket.create_connection((HOST, PORT), timeout=30)
sock = ctx.wrap_socket(raw, server_hostname=HOST)

# Send everything in one call
full = header_bytes + payload
print(f"total request size: {len(full)}")
print(f"sending...")
sock.sendall(full)
print(f"sent!")

# Receive response
buf = b""
while True:
    chunk = sock.recv(4096)
    if not chunk:
        break
    buf += chunk

print(f"\nreceived {len(buf)} bytes total")

if b"\r\n\r\n" in buf:
    idx = buf.index(b"\r\n\r\n")
    resp_headers = buf[:idx].decode("ascii", errors="replace")
    body = buf[idx+4:]
    print(f"response headers:\n{resp_headers}")
    print(f"body size: {len(body)}")
    print(f"body[:300]: {body[:300]}")
else:
    print(f"no header separator found in response!")
    print(f"raw[:500]: {buf[:500]}")

sock.close()
