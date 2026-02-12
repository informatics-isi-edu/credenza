# OAuth AS Expansion Workplan (Phased Implementation)

This workplan operationalizes [ADR-0001](./ADR-0001-narrow-oauth-profile.md) and breaks the OAuth AS expansion
into incremental, low-risk phases.

Each phase should be independently testable and deployable where possible.

---

# Phase 0 — Foundations (Safe Structural Changes)

**Goal:** Introduce structural primitives without changing external behavior.

## 0.1 Session Model Refactor
- Add immutable `grant_type` to session model.
- Add `allowed_resources` field.
- Deprecate `session_type` (maintain temporary compatibility).
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
- All session issuance paths updated to set `grant_type`.

---

# Phase 1 — Authorization Code Infrastructure

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

# Phase 2 — `/authorize` and `/token` Endpoint Expansion

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
Support:
- `authorization_code`
- `device_code`
- `urn:ietf:params:oauth:grant-type:token-exchange`

### Authorization Code Exchange
- Atomically consume auth code.
- Validate client identity.
- Validate redirect URI.
- Validate PKCE.
- Issue opaque access token bound to existing session.

Deliverable:
- Full OAuth 2.1 Authorization Code + PKCE flow operational.

---

# Phase 3 — Device Flow Compliance (RFC 8628)

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
- Create session with `grant_type=DEVICE`.
- Store upstream refresh token if provided.

Deliverable:
- Device flow interoperable with OAuth-native clients.

---

# Phase 4 — Token Exchange Hardening

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

# Phase 5 — Storage Backend Hardening

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

