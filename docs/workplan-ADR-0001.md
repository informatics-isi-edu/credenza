# OAuth AS Expansion Workplan (Phased Implementation)

This workplan operationalizes [ADR-0001](./ADR-0001-narrow-oauth-profile.md) and breaks the OAuth AS expansion
into incremental, low-risk phases.

Each phase should be independently testable and deployable where possible.

---

# Phase 0 — Foundations (Safe Structural Changes) [COMPLETE]

**Goal:** Introduce structural primitives without changing external behavior.

## 0.1 Session Model Refactor

- Add immutable `session_type` to session model.
- Add `allowed_resources` field.
- Update resource enforcement to use `allowed_resources`.

## 0.2 Lifetime Model Clarification

- Formalize sliding expiration (`PUT /session`).
- Formalize absolute lifetime caps:
    - Service: `max_ttl_seconds`
    - Device: `refresh_expires_at`
    - Interactive: internal TTL policy
- Ensure derived sessions are non-extendable.

## 0.3 Unified Client Registry (Read-Only Mode)

- Introduce unified client registry structure.
- Do not yet remove `service_auth.json`.
- Implement client lookup abstraction layer.
- Support authentication methods:
    - `client_secret`
    - `none` (PKCE)
    - `aws_presigned`
- Add registry validation scaffolding.

Deliverable:

- No external behavior change.
- All session issuance paths updated to set `session_type`.

---

# Phase 1 — Authorization Code Infrastructure [COMPLETE]

**Goal:** Implement OAuth Authorization Code + PKCE without yet enabling external clients.

## 1.1 Authorization Code Store

- Implement short-lived code storage.
- Store:
    - `session_id`
    - `client_id`
    - `redirect_uri`
    - `code_challenge`
    - `code_challenge_method`
    - `resource`
    - `scope`
    - `expires_at`
- TTL default ~5 minutes (configurable).

## 1.2 Atomic Code Consumption

- Add backend-agnostic `consume(key)` interface.
- Redis backend: use `GETDEL`.
- Postgres backend: use `DELETE ... RETURNING`.
- Memory/file backends: best-effort + startup warning.
- Remove any `used` flag logic.

## 1.3 PKCE Verification

- Implement S256-only verification.
- Reject `plain`.
- Enforce code_verifier validation during `/token`.

Deliverable:

- Authorization codes can be created and consumed atomically.
- PKCE verification functional in isolation.

---

# Phase 2 — `/authorize` and `/token` Endpoint Expansion [COMPLETE]

**Goal:** Expose OAuth Authorization Code flow for registered clients.

## 2.1 `/authorize` Endpoint

- Validate:
    - `client_id`
    - `redirect_uri` (exact match)
    - `response_type=code`
    - `scope`
    - `code_challenge`
    - `code_challenge_method=S256`
    - optional `resource`
- Enforce:
    - Client registry lookup
    - Allowed grant types
    - PKCE requirement for public clients
    - Allowed scopes
    - Allowed resources
- Reuse existing OIDC login plumbing.
- On callback:
    - Create session.
    - Generate authorization code.
    - Redirect to client.

## 2.2 `/token` Endpoint

Support grant types:

- `authorization_code`
- `device_code`
- `urn:ietf:params:oauth:grant-type:token-exchange`
- `client_credentials`

### Authorization Code Exchange

- Atomically consume auth code.
- Validate client identity.
- Validate redirect URI.
- Validate PKCE.
- Issue opaque access token bound to existing session.

Deliverable:

- Full OAuth 2.1 Authorization Code + PKCE flow operational.

---

# Phase 3 — Device Flow Compliance (RFC 8628) [COMPLETE]

**Goal:** Make existing device flow fully spec-compliant.

## 3.1 Device Authorization Endpoint

- Require `client_id`.
- Support optional client authentication.
- Validate allowed grant types.
- Validate scopes and resources.
- Persist `client_id` in device state.

## 3.2 Device Token Polling

- Enforce client_id consistency.
- Enforce polling interval.
- Create session with `session_type=DEVICE`.
- Store upstream refresh token if provided.

Deliverable:

- Device flow interoperable with OAuth-native clients.

---

# Phase 4 — Token Exchange Hardening [COMPLETE]

**Goal:** Enforce strict RFC 8693 semantics and default-deny model.

## 4.1 Subject Token Validation

- Validate subject token via session store.
- Ensure token active and resource-bound.

## 4.2 Exchange Policy Enforcement

- Default-deny.
- Enforce per-client exchange allowlist.
- No transitive exchange.
- No privilege escalation.

## 4.3 Derived Session Rules

- Short-lived.
- Non-refreshable.
- Non-extendable.

Deliverable:

- Secure, policy-driven token exchange.

---

# Phase 5 — Storage Backend Hardening [COMPLETE]

**Goal:** Guarantee production safety across supported backends.

## 5.1 Backend Interface Update

- Add `consume(key)` to backend abstraction.
- Document atomicity requirements.

## 5.2 Redis Backend

- Implement `GETDEL`.

## 5.3 Postgres Backend

- Implement `DELETE ... RETURNING`.
- Include expiration enforcement in query.

## 5.4 Backend Safety Policy

- Document:
    - Redis/Postgres required for production OAuth usage.
    - Other backends not recommended for production.

Deliverable:

- Authorization code replay protection guaranteed.

---

# Phase 6 — MCP Integration Completion

**Goal:** Validate full end-to-end OAuth + resource server integration.

## 6.1 MCP Client Flow

- Verify `/authorize` → `/token` flow.
- Validate PKCE enforcement.

## 6.2 MCP Resource Server

- Confirm introspection resource enforcement.
- Confirm `allowed_resources` maps correctly to `aud`.

## 6.3 DERIVA Token Exchange

- Implement exchange logic in `connection.py`.
- Enforce default-deny exchange policy.

Deliverable:

- Fully interoperable MCP + DERIVA flow.

---

# Phase 7 — Testing & Verification

## 7.1 Authorization Code

- Single-use enforcement.
- PKCE validation.
- Redirect URI validation.
- Replay protection under concurrency.

## 7.2 Device Flow

- Client auth validation.
- Polling interval enforcement.
- Refresh expiration enforcement.

## 7.3 Token Exchange

- Default-deny enforcement.
- No privilege escalation.
- No transitive exchange.

## 7.4 Storage Atomicity

- Concurrent `/token` requests do not issue duplicate tokens.

---

# Phase 8 — Documentation & Deployment

- Update deployment documentation:
    - Backend requirements for production.
    - Redis/Postgres recommendation.
    - Device session lifetime clarification (offline_access / 14-day default).
- Update operational runbooks.
- Add migration notes for `service_auth.json`.

---

# Phase 9 — OIDC UserInfo Endpoint

**Goal:** Expose a standard `GET /userinfo` endpoint so OIDC clients can retrieve
identity claims using their bearer token, without requiring client credentials.
This allows relying parties (e.g., deriva-mcp-ui) to be registered as public OIDC
clients -- no client secret needed.

---

## 9.1 Endpoint

`GET /userinfo` per OpenID Connect Core 1.0 section 5.3.

Authentication: `Authorization: Bearer {token}` -- the user's own session key.
No client credentials required. `get_current_session()` already handles bearer
token extraction (`util.py:38-46`) and `session_from_bearer_token()` does the
lookup, so the session resolution path is identical to `GET /session`.

Response: JSON (not a signed JWT -- plain JSON is sufficient and simpler).
Error responses: 401 for missing/invalid token, 403 for insufficient scope (if
`openid` scope enforcement is added -- see 9.3).

---

## 9.2 Claim construction

Claim normalization is already solved by `api/common/claim_mapper.py`.
`resolve_claim()` and `get_claim_map_for_realm()` are used by `session.py` and
`introspect.py` for exactly this purpose. The `/userinfo` implementation reuses
the same pattern -- no new normalization logic needed.

The `principal` returned is the composite `iss/sub` (not bare `sub`), consistent
with how the token cache key is computed in `deriva-mcp-core` and how `client.id`
is constructed in `make_session_response()`. This prevents cross-issuer collisions
(Keycloak and Globus both issue short `sub` values).

Minimum response (always present):

```json
{
  "sub": "https://auth.globus.org/abc123",
  "iss": "https://auth.globus.org"
}
```

Full response when claims are available:

```json
{
  "sub": "https://auth.globus.org/abc123",
  "iss": "https://auth.globus.org",
  "preferred_username": "alice@example.org",
  "email": "alice@example.org",
  "email_verified": "true",
  "full_name": "Alice Example"
}
```

The claim set mirrors what `make_session_response()` already returns for the
non-legacy path -- just the identity fields, without session metadata, groups,
resources, or scopes (those belong on `/session`, not `/userinfo`).

---

## 9.3 Scope enforcement

Per OIDC spec, a client must have been granted `openid` scope for the access
token to be usable at `/userinfo`. Two options:

**Option A (strict):** Check `get_effective_scopes(session)` includes `openid`;
return 403 if not. Requires clients to request `scope=openid` in the authorize
URL (deriva-mcp-ui already does this after the Phase 7 changes).

**Option B (permissive):** Return claims for any valid token regardless of scope.
Simpler, but non-conformant. Acceptable if all Credenza clients are internal and
scope hygiene is enforced at registration rather than at runtime.

Recommendation: Option A. The scope check is one line and enforces correct
client behaviour. Internal clients that need `/userinfo` should request `openid`.

---

## 9.4 Discovery document

Add `userinfo_endpoint` to the RFC 8414 metadata in `rest/metadata.py`:

```python
"userinfo_endpoint": f"{base_url}/userinfo",
```

---

## 9.5 Implementation sketch

New file `rest/userinfo.py` -- approximately 60 lines including imports:

```python
@bp.get("/userinfo")
def userinfo():
    sid, session = get_current_session()  # handles Bearer header
    if not session:
        abort(401)

    # Scope enforcement (Option A)
    if "openid" not in get_effective_scopes(session):
        abort(403)

    realm = session.session_metadata.realm
    cmap = get_claim_map_for_realm(realm, current_app.config["REALM_CLAIM_MAPS"])
    sub = resolve_claim(session, "sub", session.userinfo.get("sub"), cmap)
    iss = resolve_claim(session, "iss", session.userinfo.get("iss"), cmap)
    email = resolve_claim(session, "email", session.userinfo.get("email"), cmap)
    name = resolve_claim(session, "full_name", session.userinfo.get("name"), cmap)
    uname = resolve_claim(session, "preferred_username",
                          session.userinfo.get("preferred_username"), cmap)
    ev = resolve_claim(session, "email_verified",
                       session.userinfo.get("email_verified"), cmap)

    return jsonify({k: v for k, v in {
        "sub": f"{iss}/{sub}" if iss else sub,
        "iss": iss,
        "preferred_username": uname,
        "email": email,
        "email_verified": ev,
        "full_name": name,
    }.items() if v is not None})
```

Register the blueprint in `app.py` alongside the existing routes.

---

## 9.6 Tests

- Valid token with `openid` scope → 200 with `sub` present
- Valid token without `openid` scope → 403
- Missing Authorization header → 401
- Expired/invalid token → 401
- `sub` is composite `iss/sub` when `iss` is present
- `sub` is bare `sub` when `iss` is absent (e.g., Keycloak with no `iss` in userinfo)

Estimated: ~8 tests, fits within the existing `test/rest/` pattern.

---

## 9.7 Client migration (deriva-mcp-ui)

Once `/userinfo` is live:

1. Replace the temporary `GET /session` call in `auth.py` with `GET /userinfo`
2. Read `response["sub"]` as the principal (already `iss/sub` composite)
3. No other changes needed -- the chatbot is already registered as a public client
   and already requests `scope=openid`

---

