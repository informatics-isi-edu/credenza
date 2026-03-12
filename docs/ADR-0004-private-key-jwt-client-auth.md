# ADR-0004: private_key_jwt Client Authentication (RFC 7523)

## 1. Status

**Proposed (Blue-Sky)**
Decision Date: 2026-03-12

### Review History

| Date       | Status          | Notes                                                            |
|------------|-----------------|------------------------------------------------------------------|
| 2026-03-12 | Proposed        | Initial draft; blue-sky reference, not currently prioritized     |

---

## 2. Context

`private_key_jwt` is a client authentication method defined in RFC 7523
(JSON Web Token Profile for OAuth 2.0 Client Authentication) and referenced
by OpenID Connect Core. The client proves its identity by presenting a
signed JWT (a `client_assertion`) rather than a shared secret or a TLS
certificate. The AS verifies the JWT signature using the client's registered
public key.

This method has several properties that make it attractive:

- **No shared secret**: the client's private key never leaves its own
  environment. The AS only holds the corresponding public key.
- **Asymmetric proof**: possession of the signing key is demonstrated
  cryptographically at each request.
- **Standard**: widely supported by OAuth clients (authlib, spring-security-oauth2,
  oidc-client-ts, etc.) and required by FAPI 2.0.
- **Key rotation**: clients can rotate their signing keys without coordinating
  with the AS, provided the AS fetches from a JWKS URI.

The primary distinction from mTLS (ADR-0003): `private_key_jwt` operates
entirely at the application layer (a JWT in the POST body), requiring no
proxy-level certificate forwarding. It is more portable across deployment
configurations but does not provide the network-layer binding that mTLS
offers (no sender-constraint without additional mechanism).

### 2.1 Why Blue-Sky

`private_key_jwt` is not currently prioritized because:

- Credenza's current client population (internal M2M services) is adequately
  served by `client_secret` and `aws_presigned`.
- mTLS (ADR-0003) addresses the no-shared-secret requirement for environments
  that already operate PKI.
- `private_key_jwt` requires JTI replay prevention storage -- an additional
  operational concern.
- FAPI 2.0 compliance is a future objective, not an immediate one.

This ADR is recorded as a reference design so that if `private_key_jwt`
is needed (e.g., for FAPI compliance, or for clients that cannot use mTLS),
the implementation path is clear and pre-analyzed.

### 2.2 Relationship to Existing Infrastructure

`authlib` is already a core Credenza dependency and provides JWT signature
verification and JWKS handling. No additional cryptographic libraries are
needed. The adapter interface (`AdapterInterface`, `ProofContext`,
`AdapterResult`) is the natural insertion point, consistent with all other
authentication methods.

---

## 3. Decision

Credenza SHALL implement a `private_key_jwt` client authentication adapter
when prioritized, following RFC 7523 and the OpenID Connect Core
`private_key_jwt` authentication method profile.

`client_secret_jwt` (HMAC-based JWT authentication, the other method defined
in OIDC Core) SHALL NOT be implemented. It provides weaker security properties
than `private_key_jwt` (symmetric key, same risks as `client_secret`) and
is not required by any conformance profile Credenza is likely to pursue.

---

## 4. Architecture

### 4.1 Adapter Implementation

A new file `credenza/api/auth/client/adapters/impl/private_key_jwt.py`:

```python
@register_adapter
class PrivateKeyJwtAdapter(AdapterInterface[PrivateKeyJwtConfig]):
    ADAPTER_NAME = "private_key_jwt"
    SUPPORTED_AUTH_METHODS = ("private_key_jwt",)
```

`PrivateKeyJwtConfig` (frozen dataclass extending `AdapterConfig`) fields:

| Field         | Type            | Description                                              |
|---------------|-----------------|----------------------------------------------------------|
| `jwk`         | `dict` (optional) | Inline JWK (public key). Mutually exclusive with `jwks_uri`. |
| `jwks_uri`    | `str` (optional)  | URL of the client's JWKS endpoint. Fetched and cached.   |
| `jwks_cache_ttl` | `int`          | Seconds to cache JWKS (default: 3600). Supports key rotation. |
| `expected_aud`| `str` (optional)  | Expected `aud` claim. Defaults to the token endpoint URL. |
| `max_exp_secs`| `int`             | Maximum allowed assertion lifetime (default: 300s).      |

Exactly one of `jwk` or `jwks_uri` MUST be configured. Both present is
a configuration error.

### 4.2 JWT Assertion Format

Per RFC 7523 / OIDC Core, the client presents:

```
POST /token
Content-Type: application/x-www-form-urlencoded

client_id=<client_id>
&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
&client_assertion=<signed JWT>
&grant_type=...
```

The signed JWT MUST contain:

| Claim | Requirement | Value                                              |
|-------|-------------|----------------------------------------------------|
| `iss` | REQUIRED    | `client_id`                                        |
| `sub` | REQUIRED    | `client_id`                                        |
| `aud` | REQUIRED    | Token endpoint URL (or AS issuer URL)              |
| `jti` | REQUIRED    | Unique identifier; used for replay prevention      |
| `exp` | REQUIRED    | Expiration time; MUST be within `max_exp_secs`     |
| `iat` | RECOMMENDED | Issued-at time                                     |

The JWT header MUST specify a supported algorithm (`alg`). Supported
algorithms SHALL be limited to asymmetric signing algorithms:
RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512.
`none` and symmetric algorithms (HS*) SHALL be rejected.

### 4.3 Authentication Flow

`authenticate()` logic:

1. Detect `client_assertion_type` in `proof_context.form`. If not
   `urn:ietf:params:oauth:client-assertion-type:jwt-bearer`, raise
   `AdapterAuthError` (wrong method or no assertion).
2. Extract `client_assertion` JWT from form.
3. Resolve the client's public key:
   - If `jwk` is configured: use directly.
   - If `jwks_uri` is configured: fetch from URI (with caching).
     If fetch fails: raise `AdapterError` (server-side failure).
4. Verify the JWT:
   - Signature valid for the resolved key.
   - Algorithm is in the allowed set (not `none`, not symmetric).
   - `iss` == `sub` == `client_id`.
   - `aud` matches the configured or default expected audience.
   - `exp` is in the future and within `max_exp_secs` of `iat` (or now).
   - JWT is not expired.
5. Check JTI replay cache:
   - If `jti` is found in the cache: raise `AdapterAuthError` (replay).
   - If not found: store `jti` in cache with TTL = `exp - now`.
6. On success, return `AdapterResult` with
   `Subject(provider="private_key_jwt", subject_id=client_id)`.

`auth_context` SHALL include: `method`, `client_id`, `jti`, `alg`,
`key_id` (from JWT header `kid` if present), `issued_at`.

### 4.4 JWKS Fetching and Caching

When `jwks_uri` is configured, the adapter must fetch and cache the
client's public keys:

- Cache key: `jwks_uri`
- Cache TTL: `jwks_cache_ttl` (default 3600s)
- On cache miss or expiry: HTTP GET the URI, parse JWK Set, cache result
- On fetch failure: raise `AdapterError` (do not fall back to stale cache
  silently; log and fail to avoid accepting assertions with unknown keys)
- Key selection: use JWT header `kid` to select the matching key from the
  JWK Set if present; otherwise attempt all keys of the matching `alg`

authlib's `JsonWebKeySet` handles JWK Set parsing and key selection.

A simple in-memory LRU cache (e.g., `functools.lru_cache` with manual TTL,
or a small `cachetools.TTLCache`) is sufficient for the initial implementation.
In multi-worker deployments, JWKS is fetched per-worker -- this is acceptable
given the caching TTL.

### 4.5 JTI Replay Prevention

Each `jti` must be accepted at most once within the assertion's valid
lifetime. This requires a short-lived key-value store.

**Options:**

1. **Session store** (reuse existing infrastructure): add a `jti_cache` key
   namespace to the existing session store. Simple, no new dependencies.
   Works correctly with Redis/Valkey (shared across workers). Memory backend
   provides in-process-only protection (adequate for single-worker dev).

2. **Standalone in-memory dict with TTL cleanup**: simpler implementation,
   but per-worker -- does not protect against replay across multiple workers.
   Not recommended for production multi-worker deployments.

**Decision**: Use the session store JTI namespace (option 1). Implement
`store.set_jti(jti, ttl)` and `store.has_jti(jti)` as thin wrappers over
the existing key-value backend. This reuses the existing Redis/Postgres/Memory
abstraction with correct multi-worker semantics.

### 4.6 Audience Validation

The `aud` claim in the client assertion must match the AS's token endpoint
URL. This is derived from `BASE_URL`:

```python
expected_aud = f"{base_url}/token"
```

authlib's JWT validation handles this. The `expected_aud` MAY also be
configured explicitly per client record to support non-standard clients
that use the issuer URL as `aud` rather than the token endpoint URL.

### 4.7 Algorithm Policy

The following algorithms SHALL be supported:

| Algorithm | Type       | Notes                                                |
|-----------|------------|------------------------------------------------------|
| RS256     | RSA-PKCS1v15 | Minimum 2048-bit key; widely supported             |
| RS384     | RSA-PKCS1v15 |                                                    |
| RS512     | RSA-PKCS1v15 |                                                    |
| PS256     | RSA-PSS    | Preferred over RS* for new deployments; FAPI 2.0 required |
| PS384     | RSA-PSS    |                                                    |
| PS512     | RSA-PSS    |                                                    |
| ES256     | ECDSA P-256 | Compact keys; preferred for constrained environments |
| ES384     | ECDSA P-384 |                                                    |
| ES512     | ECDSA P-521 |                                                    |

`none` and all symmetric algorithms (HS256, HS384, HS512) SHALL be
explicitly rejected regardless of what the JWT header specifies.

The allowed algorithm set MAY be restricted further per client via a
`allowed_algorithms` config field if needed.

### 4.8 Client Registry Configuration

```json
{
  "mcp-client": {
    "public": false,
    "auth": {
      "adapter": "private_key_jwt",
      "jwks_uri": "https://mcp-client.example.com/.well-known/jwks.json",
      "jwks_cache_ttl": 3600,
      "max_exp_secs": 300
    },
    "allowed_grant_types": ["authorization_code"],
    "allowed_redirect_uris": ["https://mcp-client.example.com/callback"],
    "allowed_resources": ["https://mcp.example.com"]
  }
}
```

Inline JWK (for simpler deployments without a JWKS endpoint):

```json
{
  "auth": {
    "adapter": "private_key_jwt",
    "jwk": {
      "kty": "EC",
      "crv": "P-256",
      "x": "...",
      "y": "..."
    }
  }
}
```

### 4.9 Metadata Endpoint

`token_endpoint_auth_methods_supported` SHALL include `private_key_jwt`
when the adapter is registered. The metadata response SHOULD also include
`token_endpoint_auth_signing_alg_values_supported` listing the accepted
algorithms (RS256, PS256, ES256, etc.).

---

## 5. Acceptance Criteria

1. `PrivateKeyJwtAdapter` implements `AdapterInterface` and passes
   `__init_subclass__` validation.
2. `from_dict()` validates that exactly one of `jwk` or `jwks_uri` is
   present; raises `ValueError` on invalid config.
3. JWT signature verification succeeds for all supported algorithms.
4. `none` and symmetric algorithms are rejected at verification time.
5. `iss`, `sub`, `aud`, `exp` claims are validated per spec.
6. `exp` is bounded by `max_exp_secs`.
7. JTI replay is detected and rejected on the second presentation.
8. JWKS URI fetch failures raise `AdapterError` (not `AdapterAuthError`).
9. JWKS cache is respected within TTL; re-fetched after TTL expires.
10. Session store JTI namespace (`set_jti`, `has_jti`) is implemented
    across Memory, Redis, and Postgres backends.
11. Metadata endpoint includes `private_key_jwt` in supported auth methods.
12. Tests cover: valid assertion, expired assertion, future assertion (exp
    too far), jti replay, algorithm `none` rejection, HS256 rejection,
    aud mismatch, iss/sub mismatch, JWKS fetch failure, cache hit/miss.

---

## 6. Consequences

### Positive

- No shared secret; the AS holds only the client's public key.
- Key rotation is operationally simple when `jwks_uri` is used -- the
  client rotates its keys and the AS picks them up automatically within
  the cache TTL.
- Portable: works over standard HTTPS with no proxy-level configuration
  changes (unlike mTLS).
- Required for FAPI 2.0 compliance.
- authlib already handles JWT and JWKS -- implementation complexity is
  lower than mTLS's proxy configuration surface.

### Negative

- JTI replay cache requires session store participation; adds a new key
  namespace with per-request writes.
- JWKS URI fetching introduces an outbound HTTP dependency per adapter
  instance (mitigated by caching).
- In multi-worker deployments, JTI replay protection requires Redis/Valkey
  or Postgres -- the Memory backend does not provide cross-worker protection.
- Assertions are short-lived by design; clock skew between client and AS
  must be managed (a small tolerance, e.g., 30s, is typically acceptable).
- No network-layer binding: unlike mTLS, a leaked `client_assertion` JWT
  can be replayed within its validity window by any party (mitigated by
  short `exp` and JTI replay prevention, but not eliminated).

---

## 7. Alternatives Considered

### 7.1 client_secret_jwt

HMAC-based JWT client authentication using a shared secret. Rejected --
it provides no advantage over `client_secret_post` in terms of secret
management (both require a shared secret), and adds JWT verification
overhead without the asymmetric security benefit.

### 7.2 PAR + private_key_jwt (FAPI 2.0 Full Profile)

Pushed Authorization Requests (RFC 9126) combined with `private_key_jwt`
is the full FAPI 2.0 client authentication profile. PAR is out of scope
for this ADR. If FAPI 2.0 compliance is pursued, PAR would be a separate
ADR that builds on this one.

### 7.3 mTLS as Sufficient Substitute

For internal workloads, mTLS (ADR-0003) may provide equivalent security
with simpler JWT handling (no JTI cache, no JWKS fetch). `private_key_jwt`
is the better choice for external clients that cannot use mTLS, or for
FAPI compliance scenarios. The two methods are complementary, not competing.

---

## 8. Summary

`private_key_jwt` is a clean, portable, no-shared-secret client authentication
method that fits naturally into Credenza's adapter architecture. The primary
implementation concerns are JTI replay prevention (addressed via the existing
session store) and JWKS caching (addressed via authlib and a simple TTL cache).
It is recorded here as a blue-sky reference design for use when FAPI 2.0
compliance or external client support makes it a priority.