#!/usr/bin/env python3
"""
Test the HTTP/1.1 protocol + WASM module via raw TLS socket.
Runs the same 6 tests as the previous deploy.py but using HTTP/1.1.
"""
import ssl
import socket
import json
import sys
import os

HOST = "localhost"
PORT = 8445

def make_tls_conn():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection((HOST, PORT), timeout=30)
    return ctx.wrap_socket(raw, server_hostname=HOST)

def send_http(sock, method, path, body=None, auth_token=None, connection_close=False):
    req = f"{method} {path} HTTP/1.1\r\nHost: {HOST}\r\n"
    if body:
        req += f"Content-Length: {len(body)}\r\nContent-Type: application/json\r\n"
    if auth_token:
        req += f"Authorization: Bearer {auth_token}\r\n"
    if connection_close:
        req += "Connection: close\r\n"
    req += "\r\n"
    sock.sendall(req.encode())
    if body:
        sock.sendall(body)

def recv_http(sock):
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("connection closed before headers")
        buf += chunk
    header_end = buf.index(b"\r\n\r\n")
    header_section = buf[:header_end].decode("ascii")
    body_start = header_end + 4

    status_line = header_section.split("\r\n")[0]
    status_code = int(status_line.split(" ", 2)[1])

    content_length = 0
    for line in header_section.split("\r\n")[1:]:
        if line.lower().startswith("content-length:"):
            content_length = int(line.split(":", 1)[1].strip())

    body = buf[body_start:]
    while len(body) < content_length:
        chunk = sock.recv(4096)
        if not chunk:
            break
        body += chunk
    return status_code, body[:content_length]

def http_request(method, path, body=None, auth_token=None):
    sock = make_tls_conn()
    send_http(sock, method, path, body, auth_token, connection_close=True)
    status, resp_body = recv_http(sock)
    sock.close()
    return status, resp_body

def test_healthz():
    status, body = http_request("GET", "/healthz")
    assert status == 200, f"Expected 200, got {status}: {body}"
    data = json.loads(body)
    assert data["status"] == "ok", f"Expected ok, got {data}"
    print("  PASS: healthz")

def test_readyz(token):
    status, body = http_request("GET", "/readyz", auth_token=token)
    assert status == 200, f"Expected 200, got {status}: {body}"
    data = json.loads(body)
    assert data["status"] == "ready", f"Expected ready, got {data}"
    print("  PASS: readyz")

def test_wasm_load(token, cwasm_path):
    with open(cwasm_path, "rb") as f:
        cwasm_bytes = f.read()
    payload = json.dumps({
        "wasm_load": {
            "name": "example",
            "bytes": list(cwasm_bytes),
            "permissions": {
                "http_hosts": ["*"],
                "kv_namespaces": ["default"]
            }
        }
    }).encode()
    print(f"  DEBUG: wasm_load payload size = {len(payload)} bytes")
    status, body = http_request("POST", "/data", body=payload, auth_token=token)
    assert status == 200, f"wasm_load failed ({status}): {body}"
    print(f"  DEBUG: wasm_load response length={len(body)}, first 200 chars: {body[:200]}")
    data = json.loads(body)
    assert "ok" in str(data).lower() or "loaded" in str(data).lower() or "success" in str(data).lower(), f"Unexpected: {data}"
    print(f"  PASS: wasm_load ({len(cwasm_bytes)} bytes)")

def test_wasm_call(token, func_name, args=None, expect_contains=None, label=None):
    payload = json.dumps({
        "wasm_call": {
            "app": "example",
            "function": func_name,
            "args": args or []
        }
    }).encode()
    status, body = http_request("POST", "/data", body=payload, auth_token=token)
    assert status == 200, f"wasm_call {func_name} failed ({status}): {body}"
    data = json.loads(body)
    result_str = json.dumps(data)
    if expect_contains:
        assert expect_contains.lower() in result_str.lower(), f"Expected '{expect_contains}' in: {result_str}"
    print(f"  PASS: {label or func_name}")
    return data

def test_wasm_list(token):
    payload = json.dumps({"wasm_list": {}}).encode()
    status, body = http_request("POST", "/data", body=payload, auth_token=token)
    assert status == 200, f"wasm_list failed ({status}): {body}"
    data = json.loads(body)
    print(f"  PASS: wasm_list -> {data}")
    return data

def main():
    token = os.environ.get("OIDC_TOKEN")
    cwasm_path = os.environ.get("CWASM_PATH", "/home/ubuntu/projects/wasm_example.cwasm")

    if not token:
        print("ERROR: Set OIDC_TOKEN environment variable")
        sys.exit(1)

    print("\n=== Testing HTTP/1.1 Protocol ===\n")

    print("[1] Basic endpoints:")
    test_healthz()
    test_readyz(token)

    print("\n[2] WASM load:")
    test_wasm_load(token, cwasm_path)

    print("\n[3] WASM list:")
    test_wasm_list(token)

    print("\n[4] WASM function calls:")
    test_wasm_call(token, "hello", [], expect_contains="hello", label="hello")
    test_wasm_call(token, "get-random", [], label="get-random")
    test_wasm_call(token, "get-time", [], label="get-time")

    # KV store test
    test_wasm_call(token, "kv-store", [
        {"name": "key", "type": "string", "value": "test-key"},
        {"name": "value", "type": "string", "value": "test-value-http"}
    ], label="kv-store")
    test_wasm_call(token, "kv-read", [
        {"name": "key", "type": "string", "value": "test-key"}
    ], expect_contains="test-value-http", label="kv-read")

    # HTTPS fetch
    test_wasm_call(token, "fetch-headlines", [], label="fetch-headlines")

    print("\n=== ALL TESTS PASSED ===\n")

if __name__ == "__main__":
    main()
