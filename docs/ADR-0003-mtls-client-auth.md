# ADR-0003: mTLS Client Authentication (RFC 8705)

## 1. Status

**Proposed**
Decision Date: 2026-03-12

### Review History

| Date       | Status   | Notes                              |
|------------|----------|------------------------------------|
| 2026-03-12 | Proposed | Initial draft                      |

---

## 2. Context

Credenza currently supports two client authentication methods:

- `client_secret` (HTTP Basic or form post, with optional bcrypt hash)
- `aws_presigned` (AWS STS presigned GetCallerIdentity, no shared secret)

Both require either a shared secret or an AWS-specific proof mechanism.
Neither is appropriate for workloads that already possess X.509 certificates
and want to use them for mutual authentication -- a pattern increasingly
common in Kubernetes environments (service mesh mTLS), enterprise PKI
deployments, and any infrastructure where certificate lifecycle is already
managed externally (e.g., SPIFFE/SPIRE, cert-manager, Vault PKI).

RFC 8705 (OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound
Access Tokens) defines how TLS client certificates can be used for OAuth
client authentication. It is a mature, widely implemented standard supported
by major OAuth AS implementations (Keycloak, Auth0, Okta, Azure AD).

It is also a prerequisite for FAPI 2.0 compliance, which Credenza may pursue
in the future (see ADR-0001 context notes on conformance certification).

### 2.1 ProofContext Already Anticipates mTLS

The existing `ProofContext` dataclass in `adapter.py` includes:

```python
tls_peer_cert: Optional[str] = None
```

This field was included at design time for exactly this purpose. The
infrastructure to carry a client certificate from the request layer into
the adapter is already present; no changes to `ProofContext` are required.

### 2.2 TLS Termination at the Proxy

Credenza runs behind a TLS-terminating reverse proxy in all supported
deployment configurations (Apache via `WSGIScriptAlias`, Traefik via
`stripPrefix`). The proxy terminates TLS and must forward the client
certificate to Flask via a request header. Flask and the adapter see
the certificate as a header value, not as a live TLS connection property.

This is standard practice and well-supported by both Apache and Traefik.
It means the mTLS adapter operates on the forwarded certificate, not on
the raw TLS handshake -- a distinction that has security implications
addressed in section 4.4.

---

## 3. Decision

Credenza SHALL implement a new `mtls` client authentication adapter
(RFC 8705) supporting both sub-methods defined by the spec:

- `tls_client_auth` -- PKI-based mutual TLS. The certificate is validated
  against a configured CA. The client is identified by matching the
  certificate's Subject DN or Subject Alternative Name against the
  registered `client_id` or a configured subject pattern.

- `self_signed_tls_client_auth` -- Fingerprint-based mutual TLS. The
  certificate is self-signed; identity is asserted by matching the
  certificate's SHA-256 thumbprint against a registered value. No CA
  validation is performed.

Both sub-methods SHALL be implemented within a single `MtlsAdapter`
class following the existing `AdapterInterface` contract.

Optionally, Credenza MAY implement certificate-bound access tokens
(RFC 8705 Section 3), storing the client certificate thumbprint (`cnf`)
in the session and exposing it in introspection responses. This is
addressed in section 3.2.

---

## 4. Architecture

### 4.1 Adapter Implementation

A new file `credenza/api/auth/client/adapters/impl/mtls.py`:

```python
@register_adapter
class MtlsAdapter(AdapterInterface[MtlsConfig]):
    ADAPTER_NAME = "mtls"
    SUPPORTED_AUTH_METHODS = ("tls_client_auth", "self_signed_tls_client_auth")
```

`MtlsConfig` (frozen dataclass extending `AdapterConfig`) fields:

| Field                   | Type            | Sub-method               | Description                                      |
|-------------------------|-----------------|--------------------------|--------------------------------------------------|
| `method`                | `str`           | both                     | `tls_client_auth` or `self_signed_tls_client_auth` |
| `ca_cert_file`          | `str` (path)    | `tls_client_auth`        | PEM file of the trusted CA or CA chain           |
| `subject_dn`            | `str` (optional)| `tls_client_auth`        | Expected Subject DN; defaults to `client_id`     |
| `san`                   | `str` (optional)| `tls_client_auth`        | Expected Subject Alternative Name (URI or DNS)   |
| `cert_thumbprint_s256`  | `str`           | `self_signed_tls_client_auth` | Hex-encoded SHA-256 thumbprint of the expected cert |

`authenticate()` logic:

1. Extract the certificate from `proof_context.tls_peer_cert`. If absent,
   raise `AdapterAuthError` (cert not presented).
2. Detect the sub-method from the configured `method` field (fail-fast if
   the presented method is not in `allowed_methods`).
3. For `tls_client_auth`:
   - Parse the certificate (DER or PEM from header).
   - Verify the certificate against the configured `ca_cert_file`.
   - Verify the certificate has not expired.
   - Match the certificate Subject DN or SAN against `subject_dn` / `san`
     (or `client_id` if neither is configured).
4. For `self_signed_tls_client_auth`:
   - Parse the certificate.
   - Compute SHA-256 thumbprint of the DER-encoded certificate.
   - Compare against `cert_thumbprint_s256` using constant-time comparison.
5. On success, return `AdapterResult` with `Subject(provider="mtls", subject_id=client_id)`.

The `auth_context` in the returned `AdapterResult` SHALL include:
`method`, `subject_dn`, `cert_thumbprint_s256`, `cert_not_after`, `issued_at`.

### 4.2 Certificate Parsing

Python's standard library `ssl` module and `cryptography` package
(already an indirect dependency via authlib) can parse X.509 certificates.
The `cryptography` package SHALL be the canonical tool for:
- DER/PEM decoding
- CA chain verification
- SAN extraction
- SHA-256 thumbprint computation

No additional dependencies are required beyond what is already present.

### 4.3 Proxy Configuration

#### Apache (wsgi_credenza.conf.in)

```apache
# Require client certificate for the token and introspect endpoints only.
# SSLVerifyClient is set per-location to avoid requiring certs on all routes.
<Location "/authn/token">
    SSLVerifyClient optional_no_ca
    SSLOptions +ExportCertData +StdEnvVars
    RequestHeader set X-Client-Cert "%{SSL_CLIENT_CERT}s" env=SSL_CLIENT_CERT
</Location>

<Location "/authn/introspect">
    SSLVerifyClient optional_no_ca
    SSLOptions +ExportCertData +StdEnvVars
    RequestHeader set X-Client-Cert "%{SSL_CLIENT_CERT}s" env=SSL_CLIENT_CERT
</Location>
```

`optional_no_ca` (not `require`) is used because certificate validation
is performed by the adapter, not Apache. Apache's role is to forward the
cert; Credenza's adapter enforces the policy.

#### Traefik (docker-compose.yml)

```yaml
- "traefik.http.middlewares.credenza-mtls.passTLSClientCert.info.notAfter=true"
- "traefik.http.middlewares.credenza-mtls.passTLSClientCert.info.notBefore=true"
- "traefik.http.middlewares.credenza-mtls.passTLSClientCert.pem=true"
- "traefik.http.routers.credenza.middlewares=credenza-stripprefix,credenza-mtls"
```

Traefik forwards the certificate as `X-Forwarded-Tls-Client-Cert` (PEM,
URL-encoded). The adapter SHALL accept this header name in addition to
`X-Client-Cert` for Traefik compatibility.

#### ProofContext population

In `rest/helpers.py`, where `ProofContext` is constructed before calling
`adapter_authenticate()`, populate `tls_peer_cert` from the request:

```python
tls_peer_cert = (
    request.headers.get("X-Client-Cert") or
    request.headers.get("X-Forwarded-Tls-Client-Cert")
)
proof_ctx = ProofContext(
    form=request.form.to_dict(flat=False),
    headers=dict(request.headers),
    tls_peer_cert=tls_peer_cert,
    ...
)
```

### 4.4 Security Considerations

**Header injection risk**: Because the certificate arrives via an HTTP header
forwarded by the proxy, a client that can reach Flask directly (bypassing the
proxy) could forge the `X-Client-Cert` header and impersonate any certificate
holder. This MUST be mitigated by:

- Network policy ensuring Flask/gunicorn is only reachable via the proxy
  (not directly from the internet or untrusted clients).
- Optionally, Apache/Traefik can be configured to strip any incoming
  `X-Client-Cert` / `X-Forwarded-Tls-Client-Cert` header before adding
  the proxy-derived value, preventing client-supplied forgery.

This is the standard mitigation for all proxy-forwarded TLS certificate
deployments and is not unique to Credenza.

**Certificate expiration**: The adapter SHALL reject expired certificates
regardless of CA validity. `cert_not_after` is checked at `authenticate()`
time.

**Replay**: Unlike `aws_presigned`, mTLS certificates are not single-use.
Rate limiting (already present) and short-lived session TTLs (configured
per `ClientRecord`) are the mitigations.

### 4.5 Certificate-Bound Access Tokens (Optional)

RFC 8705 Section 3 defines sender-constrained tokens: the access token
is cryptographically bound to the client's certificate thumbprint via a
`cnf` (confirmation) claim. Resource servers verify the thumbprint at
introspection time.

For Credenza's opaque token model, this means:

- At session creation, store `cnf.x5t#S256` (SHA-256 cert thumbprint)
  in `session.metadata`.
- At introspection, include `cnf: {"x5t#S256": "<thumbprint>"}` in the
  response if present.
- Resource servers can then verify the presenting client's certificate
  thumbprint matches the introspection response.

This is additive and does not change the token issuance flow. It is
marked optional for the initial implementation; the session model already
supports arbitrary `metadata` fields. Full sender-constraint enforcement
requires cooperation from resource servers and is out of scope for
Credenza alone.

### 4.6 Client Registry Configuration

```json
{
  "mcp-rs": {
    "public": false,
    "auth": {
      "adapter": "mtls",
      "method": "self_signed_tls_client_auth",
      "cert_thumbprint_s256": "a3b4c5..."
    },
    "allowed_grant_types": ["client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"],
    "allowed_resources": ["https://mcp.example.com"],
    "allowed_token_exchange_targets": ["https://deriva.example.com"]
  }
}
```

### 4.7 Metadata Endpoint

`token_endpoint_auth_methods_supported` in the RFC 8414 metadata response
SHALL be updated to include `tls_client_auth` and `self_signed_tls_client_auth`
when the `mtls` adapter is registered.

---

## 5. Acceptance Criteria

1. `MtlsAdapter` implements `AdapterInterface` and passes `__init_subclass__` validation.
2. `from_dict()` validates required fields per sub-method and raises `ValueError` on invalid config.
3. `tls_client_auth`: CA validation, expiry check, and Subject DN / SAN matching are implemented.
4. `self_signed_tls_client_auth`: SHA-256 thumbprint computed and compared constant-time.
5. `ProofContext.tls_peer_cert` is populated from `X-Client-Cert` and `X-Forwarded-Tls-Client-Cert` headers in `helpers.py`.
6. Apache and Traefik proxy configs documented and tested in integration.
7. Header stripping (forgery mitigation) documented in deployment guide.
8. Tests cover: successful auth (both sub-methods), expired cert rejection, thumbprint mismatch, CA validation failure, missing cert, method not in `allowed_methods`.
9. Metadata endpoint lists both auth methods.

---

## 6. Consequences

### Positive

- Enables certificate-based M2M authentication without shared secrets.
- Natural fit for Kubernetes / service mesh environments (SPIFFE/SPIRE, cert-manager).
- No additional Python dependencies (cryptography package already present).
- `ProofContext.tls_peer_cert` field already exists; adapter slot is ready.
- Foundation for FAPI 2.0 compliance if pursued.
- Optional certificate-bound tokens strengthen token sender-constraint guarantees.

### Negative

- Proxy configuration changes required (Apache `SSLVerifyClient`, Traefik `passTLSClientCert`).
- Header injection risk requires network-level enforcement; cannot be fully mitigated in application code alone.
- Certificate lifecycle management (rotation, revocation, CRL/OCSP) is out of scope for Credenza and must be handled by the operator.
- `self_signed_tls_client_auth` requires updating the thumbprint in the client registry on cert rotation.

---

## 7. Alternatives Considered

### 7.1 SPIFFE/SPIRE Integration Directly

Integrate with SPIFFE workload API to verify SVIDs without a proxy-forwarded
certificate. Rejected for initial implementation -- significantly higher
complexity and deployment dependency. The mTLS adapter covers the same
use case via cert forwarding with lower operational overhead.

### 7.2 Client Secret Rotation as mTLS Substitute

Use short-lived, frequently rotated client secrets to approximate mTLS
security properties. Rejected -- secret management overhead is higher
than certificate management in environments that already operate PKI.

---

## 8. Summary

The `mtls` adapter adds RFC 8705 mutual TLS client authentication to
Credenza's existing adapter framework with minimal new code. `ProofContext`
already carries the necessary field. The primary operational consideration
is proxy configuration to forward the client certificate. Both PKI-based
and fingerprint-based sub-methods are supported, covering managed PKI
environments and simpler self-signed deployments respectively.