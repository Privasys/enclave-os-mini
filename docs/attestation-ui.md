# WASM App Attestation — UI Verification Guide

## Overview

The Attestation tab provides a browser-based interface for performing **Remote Attestation (RA-TLS)** against a deployed WASM application running inside an SGX enclave. It connects to the enclave, retrieves the x.509 certificate, extracts the SGX quote, and displays all platform and workload attestation extensions, allowing users to cryptographically verify what code is running, what configuration it uses, and that the certificate was freshly generated for their request.

## How It Works

```
Browser  ──→  Management Service  ──→  Enclave (RA-TLS)
              /api/v1/apps/{id}/attest
```

1. The frontend sends a request to the management service's `/api/v1/apps/{id}/attest` endpoint, optionally including a hex challenge nonce.
2. The management service opens an RA-TLS connection to the enclave, performing two connections:
   - **Platform connection** — connects without SNI, receives the platform certificate with OIDs 1.x and 2.x.
   - **Workload connection** — connects with SNI set to the app's hostname (e.g., `wasm-app-example.apps.privasys.org`), receives the per-workload certificate with OIDs 3.x.
3. The management service parses both certificates, extracts the quote and extensions, and returns a structured JSON response.
4. The frontend renders all attestation data with inline verification.

## UI Sections

### 1. Challenge Nonce Input

Before connecting, the user provides (or auto-generates) a **32-byte random hex nonce**. This nonce is bound into the enclave's SGX report via:

```
ReportData = SHA-512( SHA-256(public_key_SPKI_DER) ‖ challenge_nonce )
```

This proves the certificate was generated **specifically for this request**, not replayed from a previous connection.

**Deterministic mode**: If no challenge is provided, the enclave uses the certificate's `NotBefore` timestamp as the binding, enabling up to 24-hour caching of certificates (useful for high-traffic scenarios).

### 2. Challenge Mode Banner

After attestation, a color-coded banner shows the verification status:

| Color | Status | Meaning |
|-------|--------|---------|
| **Emerald** | ✓ Match — freshness verified | The computed `SHA-512(pubkey_sha256 ‖ challenge)` matches the quote's `ReportData`. This proves the certificate was generated in response to your specific challenge. |
| **Red** | ✗ Mismatch | Something went wrong — the computed hash doesn't match. This could indicate replay, tampering, or a bug. |
| **Amber** | Verifying… | Verification is in progress (auto-fires when results arrive in challenge mode). |

The verification runs **entirely in the browser** using the Web Crypto API. No server-side trust required.

### 3. TLS Connection Details

Displays the negotiated TLS parameters:

- **Protocol**: The TLS version (e.g., `TLS 1.3`)
- **Cipher Suite**: The negotiated cipher (e.g., `TLS_AES_256_GCM_SHA384`)

### 4. x.509 Certificate

Shows the parsed certificate fields with descriptions and copy buttons:

| Field | Description |
|-------|-------------|
| Subject | The entity this certificate identifies (e.g., `CN=wasm-app-example,O=Privasys`) |
| Issuer | Certificate authority that issued the cert (self-signed for platform, CA-signed for workload) |
| Serial Number | Unique identifier assigned by the issuer |
| Valid From / Valid Until | Certificate validity window |
| Signature Algorithm | Cryptographic algorithm used (e.g., `ECDSA with SHA-256`) |
| Public Key SHA-256 | Fingerprint of the subject's public key used in ReportData binding |

### 5. SGX Quote

Displays the Intel SGX DCAP quote extracted from the certificate:

| Field | Description |
|-------|-------------|
| Quote Type | The attestation format (e.g., `SGX` or `TDX`) |
| Format | Binary quote format (e.g., `DCAP V4`) |
| Version | Quote structure version |
| **MRENCLAVE** | SHA-256 hash of the enclave binary. Uniquely identifies the exact enclave build. Pin this value to ensure you're talking to the correct enclave code. |
| **MRSIGNER** | Hash of the enclave signer's public key. Identifies who built the enclave. |
| **Report Data** | 64-byte binding: `SHA-512(SHA-256(pubkey) ‖ nonce)`. In challenge mode, the UI auto-verifies this against the submitted nonce. |
| OID | The x.509 extension OID containing the raw quote (`1.2.840.113741.1.13.1.0`) |

The **Report Data** field includes inline verification badges when in challenge mode.

### 6. Platform Attestation Extensions (OIDs 1.x / 2.x)

Enclave-wide configuration attestation. These prove the enclave's runtime state:

| OID | Label | Description |
|-----|-------|-------------|
| `1.3.6.1.4.1.65230.1.1` | Config Merkle Root | Hash of the enclave configuration tree. Changes if any config parameter is modified. |
| `1.3.6.1.4.1.65230.2.1` | Egress CA Hash | Hash of the CA certificate used for egress TLS connections from the enclave. |
| `1.3.6.1.4.1.65230.2.5` | Combined Workloads Hash | Aggregate hash of **all loaded WASM workloads**. Proves which code is running across all apps. |
| `1.3.6.1.4.1.65230.2.7` | Attestation Servers Hash | Hash of the attestation server list the enclave trusts for quote verification. |

### 7. Workload Attestation Extensions (OIDs 3.x)

Per-workload attestation, retrieved via the **SNI-routed** second connection. Displayed in an emerald-accented section:

| OID | Label | Description |
|-----|-------|-------------|
| `1.3.6.1.4.1.65230.3.1` | Workload Config Merkle Root | Merkle root of the specific workload's configuration tree. |
| `1.3.6.1.4.1.65230.3.2` | Workload Code Hash | SHA-256 hash of the compiled WASM bytecode (`.cwasm`). Compared against the uploaded hash from the database. |
| `1.3.6.1.4.1.65230.3.4` | Workload Key Source | How the workload's encryption keys are sourced, typically `generated` (hex-encoded UTF-8). |

The **Workload Code Hash** (OID 3.2) is automatically compared against the CWASM hash stored in the database from the reproducible build. If they match, a green "✓ Verified — matches uploaded CWASM hash" badge is shown. A mismatch shows a red warning.

OIDs 3.3 and 3.4 whose values are UTF-8 text (not hashes) are automatically decoded from hex and displayed as readable text alongside the raw hex.

### 8. PEM Certificates

Both the Platform PEM and Workload PEM certificates are displayed in full, with:
- **Copy** button for clipboard
- **Download** button to save as `.pem` file

### 9. Verification Code Snippet

In challenge mode, the UI generates a standalone JavaScript snippet that the user can paste into their browser's developer console to independently verify the ReportData binding:

```javascript
const pubkeySha256 = "<from_certificate>";
const challenge    = "<your_nonce>";
const reportData   = "<from_sgx_quote>";

(async () => {
  const input = new Uint8Array([...hex2buf(pubkeySha256), ...hex2buf(challenge)]);
  const hash  = await crypto.subtle.digest('SHA-512', input);
  console.log(buf2hex(hash) === reportData.toLowerCase() ? "✓ MATCH" : "✗ MISMATCH");
})();
```

## Trust Model

The attestation UI enables **zero-trust verification** with the following guarantees:

| What is verified | How |
|-----------------|-----|
| The enclave is genuine SGX hardware | DCAP quote signature verification by Intel attestation infrastructure |
| The enclave runs the correct code | MRENCLAVE in the quote matches a known-good value |
| The certificate is fresh | Challenge nonce bound into ReportData (SHA-512 binding) |
| The enclave configuration is correct | Config Merkle Root covers all runtime parameters |
| The correct WASM app is loaded | Per-workload Code Hash (OID 3.2) matches the reproducibly built `.cwasm` |
| The WASM app has expected permissions | Workload Config Merkle Root covers permissions |
| No other unexpected apps are loaded | Combined Workloads Hash (OID 2.5) covers all apps |

## API Reference

### `GET /api/v1/apps/{id}/attest?challenge={hex}`

**Query Parameters:**
- `challenge` (optional): 32–128 hex character nonce (16–64 bytes). Omit for deterministic mode.

**Response:**
```json
{
  "certificate": {
    "subject": "CN=wasm-app-example,O=Privasys",
    "issuer": "CN=Privasys Intermediate CA",
    "serial_number": "...",
    "not_before": "2026-03-18T09:00:00Z",
    "not_after": "2026-03-19T09:00:00Z",
    "signature_algorithm": "ECDSA-SHA256",
    "public_key_sha256": "a1b2c3..."
  },
  "pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
  "quote": {
    "type": "SGX",
    "oid": "1.2.840.113741.1.13.1.0",
    "is_mock": false,
    "version": 4,
    "mr_enclave": "d5b176eba433...",
    "mr_signer": "...",
    "report_data": "...",
    "format": "DCAP V4"
  },
  "extensions": [
    { "oid": "1.3.6.1.4.1.65230.1.1", "label": "Config Merkle Root", "value_hex": "..." },
    { "oid": "1.3.6.1.4.1.65230.2.5", "label": "Combined Workloads Hash", "value_hex": "..." }
  ],
  "app_extensions": [
    { "oid": "1.3.6.1.4.1.65230.3.1", "label": "Workload Config Merkle Root", "value_hex": "..." },
    { "oid": "1.3.6.1.4.1.65230.3.2", "label": "Workload Code Hash", "value_hex": "..." },
    { "oid": "1.3.6.1.4.1.65230.3.4", "label": "Workload Key Source", "value_hex": "67656e657261746564" }
  ],
  "app_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
  "tls": {
    "version": "TLS 1.3",
    "cipher_suite": "TLS_AES_256_GCM_SHA384"
  },
  "challenge_mode": true,
  "challenge": "a1b2c3d4...",
  "cwasm_hash": "68237228bdeb0b13..."
}
```
