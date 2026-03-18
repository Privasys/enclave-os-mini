# WASM App Explorer

A standalone, zero-dependency static HTML tool for exploring WASM applications deployed on Enclave OS Mini. No authentication required — connect directly to any management service endpoint to inspect attestation data and test API functions.

## Features

### Attestation Tab
- **Challenge-based freshness verification** — generates a random nonce, verifies it was bound into the SGX quote's ReportData via `SHA-512(SHA-256(pubkey) ‖ nonce)`
- **x.509 certificate inspection** — subject, issuer, validity, signature algorithm, public key fingerprint
- **SGX quote analysis** — MRENCLAVE, MRSIGNER, ReportData, quote type and format
- **Platform extensions** (OIDs 1.x/2.x) — Config Merkle Root, Egress CA Hash, Combined Workloads Hash
- **Workload extensions** (OIDs 3.x) — per-app code hash, config root, key source
- **CWASM hash verification** — compares the in-quote code hash (OID 3.2) against the database-stored hash
- **PEM download** — export both platform and workload certificates

### API Testing Tab
- **WIT schema discovery** — auto-introspects the WASM component's exported functions and their typed signatures
- **Type-aware parameter inputs** — string, number, boolean toggle, enum dropdown, JSON textarea for complex types
- **Function signature display** — shows the full WIT signature with color-coded types
- **Response panel** — status code, elapsed time, pretty-printed JSON, copy button
- **Call history** — last 20 calls with replay capability

## Usage

Open `index.html` in any modern browser. No build step, no server required.

### Connection Options

**Option 1 — Full URL:**
```
https://api.developer.privasys.org/api/v1/apps/wasm-app-example
```

**Option 2 — Separate fields:**
- Base URL: `https://api.developer.privasys.org`
- App name: `wasm-app-example`

### CORS

The management service must allow CORS from the origin serving this page. If opening locally via `file://`, some browsers block fetch requests. Use a simple HTTP server:

```bash
python3 -m http.server 8000
# or
npx serve .
```

## Files

| File | Purpose |
|------|---------|
| `index.html` | Main page with connection screen and layout |
| `style.css` | All styles — supports light/dark mode via `prefers-color-scheme` |
| `explorer.js` | Application logic — attestation, API testing, WIT type handling |

## Browser Support

Requires a modern browser with:
- `fetch` API
- `crypto.subtle` (for ReportData verification)
- CSS custom properties
- ES2020+
