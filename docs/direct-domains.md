# Direct Domains

A direct domain is an adopter's own hostname whose TLS ends in the enclave
with a publicly trusted certificate. A browser can reach it like any website,
and the only party that sees the traffic in the clear is the enclave: the
platform gateway splices the connection at L4 by SNI and never holds a key.

This page describes direct domains on the WASM runtime. The protocol and
policy core is the host-tested crate `crates/enclave-os-direct`; the enclave
glue is `enclave/src/direct.rs`. Both build with the `wasm` feature.

## Who decides which names an app serves

Only the app's owner. The names come from an owner-signed app policy, the
same document and approval binding the container runtime uses:

```
PUT /api/v1/apps/<name>/policy
{"document": {"v": 1, "app_id": "<32 hex>", "seq": <n>, "domains": ["shop.example.com"]},
 "approval_token": "<step-up token from the identity provider>"}
```

The approval token is the authority, so the route needs no platform role. The
enclave verifies the token (signature, issuer, audience, expiry), checks that
it is a step-up (`amr` contains `webauthn`) and that its `vault_op` binds
exactly this document, sequence and expiry. The first accepted document pins
its approver; afterwards only a newer document that approver signed is
accepted. A document without `domains` keeps the approved list, an explicit
`[]` removes it.

Direct domains need a vault-backed app: the state below is sealed under the
app's vault-held key, and the ACME account key derives from it.

## How the certificate is obtained

The enclave obtains its own certificate from Let's Encrypt over ACME
TLS-ALPN-01 (RFC 8737), with a key generated in the enclave.

- **Account key.** A P-256 key derived from the app's vault-held key (the
  KEK): `HKDF-SHA256(secret, salt = "privasys-direct-tls/v1", info = "branch")`,
  then `HKDF-SHA256(branch, info = "privasys-acme-account/v1|<i>")` until the
  bytes are a valid scalar. The same app gets the same account on any build
  the vaults release the key to, and on the container runtime too. An
  adopter publishes a CAA record pinning issuance to that account
  (`issue "letsencrypt.org; accounturi=<account>; validationmethods=tls-alpn-01"`),
  so nobody else can obtain a certificate for the name, the platform
  included. A key rotation moves the account with the secret.
- **Status-driven issuance.** Issuance and renewal run when the control
  plane reads the status:

  ```
  GET /api/v1/apps/<name>/direct          (manager role)
  {"supported": true, "account_uri": "https://acme-v02.api.letsencrypt.org/acme/acct/<n>",
   "domains": [{"name": "shop.example.com", "issued": true,
                "not_after": "2027-01-27T10:45:21Z", "spki_sha256": "<hex>"}]}
  ```

  The request runs as a task, so its network waits suspend instead of
  blocking the enclave, and the CA's validation handshake is served while
  the order is in flight. A name is ordered only once it resolves in DNS,
  failures back off from 60 seconds to an hour, and a certificate is renewed
  when less than 30 days remain. One CA, one account: there is no retry
  against a test CA. An empty `account_uri` means the app is not
  vault-backed.

## Which certificate a handshake gets

On a direct name the enclave chooses by the ALPN the client offered:

| Client offers | Gets |
| --- | --- |
| exactly `acme-tls/1` | the challenge certificate (the CA's validation) |
| `privasys-ratls/1` | the RA-TLS leaf, minted for the direct name, with the app's full attestation |
| anything else | the publicly trusted certificate |

A connection served the publicly trusted certificate is the **direct leg**.
It is decided by the connection, never by a header, and gets the same rule as
the gateway-terminated leg: application paths need a sealed session. The
evidence endpoint is refused on it.

The app's RA-TLS leaves carry OID `1.3.6.1.4.1.65230.7.4` (direct domain
keys): one `<hostname> sha256:<hex SHA-256 of the SubjectPublicKeyInfo>` line
per issued name, sorted. A browser cannot attest the enclave, but anyone who
attests the app can check that the key serving the adopter name was born in
it.

## What survives a runtime roll

Everything an app holds for its direct domains is sealed to the host store
under a key derived from its direct-TLS branch
(`HKDF-SHA256(branch, info = "privasys-direct-state/v1")`), not under this
enclave's sealing key:

- the policy pin (approver, sequence, domains, the app's hostname);
- each issued certificate chain and its private key.

When the app is loaded again, on any build the vaults release its key to, the
names, the certificates and the status are restored with no network call and
no new approval, and the next status read renews as usual. This needs the
host store to be kept across the roll (reuse the KV directory); a build the
vaults refuse cannot read the state. The host holds the storage and can
replay an older sealed pin; the sequence still only moves forward from what
was restored, and OID 7.4 shows which keys are being served.
