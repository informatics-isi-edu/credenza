# ADR-0001: Credenza as a Narrow OAuth 2.1 Authorization Server and OIDC Relying Party

## 1. Status

**Accepted**
Decision Date: 2026-02-11

### Review History

| Date       | Status   | Notes                                                                                |
|------------|----------|--------------------------------------------------------------------------------------|
| 2026-02-10 | Proposed | Draft including token exchange constraints and acceptance criteria                   |
| 2026-02-11 | Amended  | Unified client registry and grant-based session model; clarified lifecycle semantics |
| 2026-02-11 | Amended  | Added authorization code infrastructure and backend atomicity requirements           |
| 2026-03-11 | Accepted | Phases 0-5 implemented (authorization code, token exchange, device flow, revocation) |
| 2026-03-19 | Amended  | Revised token exchange resource policy (section 5.4) to support delegated intermediary pattern; see ADR-0002 |

---

## 2. Context

Credenza originally functioned as a session broker in front of upstream
OpenID Connect (OIDC) identity providers. It authenticated users via
OIDC and issued opaque, resource-bound session tokens used by protected
services.

New requirements from OAuth-native resource servers require:

- OAuth 2.1 Authorization Code + PKCE support  
- RFC 8414 Authorization Server Metadata  
- RFC 7662 Token Introspection  
- RFC 8707 Resource Indicators  
- RFC 8693 Token Exchange  
- RFC 8628 Device Authorization  
- Audience-bound access tokens  
- Standards-compliant discovery and validation flows  

Credenza must:

- Remain identity-provider agnostic  
- Avoid duplicating upstream identity policy engines  
- Avoid becoming a full-featured IAM platform  
- Preserve its opaque, resource-bound token model  

In addition, Credenza previously maintained separate configuration
surfaces for OAuth clients and machine-to-machine (M2M) bindings.
As OAuth support expands, this separation introduces duplication
and inconsistent policy enforcement.

## 2.1 Motivation

The expansion of Credenza into a narrow OAuth 2.1 Authorization Server
is driven by concrete integration requirements from OAuth-native
clients and resource servers, particularly within the MCP ecosystem.
However, these requirements are not MCP-specific; they represent a
general class of scenarios where:

- A client authenticates via OAuth Authorization Code + PKCE.
- A resource server validates access tokens via introspection.
- The resource server must call downstream services on behalf of the user.
- Audience isolation must be preserved across service boundaries.

### OAuth-Native Clients (Authorization Code + PKCE)

Modern clients (desktop applications, CLI tools, browser-based integrations)
expect a standards-compliant OAuth Authorization Server supporting:

- Authorization Code + PKCE (OAuth 2.1 profile)
- Authorization Server metadata discovery (RFC 8414)
- Resource Indicators (RFC 8707)

These clients:

1. Discover Credenza via OAuth metadata.
2. Initiate `/authorize` with PKCE.
3. Receive an authorization code.
4. Exchange the code at `/token` for an access token.
5. Present that access token to protected resource servers.

Without a proper `/authorize` and `/token` surface, Credenza cannot
interoperate with OAuth-native clients using standardized flows.

### Resource Servers (Introspection + Token Exchange)

Resource servers must:

- Validate incoming bearer tokens via introspection (RFC 7662).
- Enforce audience isolation via resource indicators (RFC 8707).
- Optionally perform token exchange (RFC 8693) when accessing
  downstream services on behalf of an authenticated user.

In MCP deployments, for example:

- An MCP client obtains an access token scoped to `mcp:deriva-ml`.
- The MCP server validates the token via `/introspect`.
- The MCP server then exchanges the token for a `deriva:*`-scoped token
  in order to call DERIVA REST APIs on behalf of the user.

This pattern generalizes to any architecture where:

- A front-end service receives user-bound tokens.
- That service must call one or more downstream services.
- Audience boundaries must be preserved.
- Privilege escalation must be prevented.

Supporting this securely requires:

- Default-deny token exchange.
- Explicit per-client exchange allowlists.
- Non-transitive derived tokens.
- Strict preservation of canonical identity claims.
- Clear separation between identity, audience, and authorization domains.

### Why These Changes Are Necessary

Supporting these patterns requires Credenza to:

- Implement full OAuth AS flows (not just upstream OIDC login).
- Enforce audience isolation consistently across all grant types.
- Issue opaque, resource-bound access tokens.
- Provide reliable introspection for downstream validation.
- Support secure, policy-driven token exchange.
- Guarantee single-use authorization codes with atomic replay protection.

The unified client registry enables consistent policy enforcement across:

- OAuth clients (authorization_code, device_code).
- Machine-to-machine proof-based service clients.
- Token exchange participants.
- Introspection clients.

By introducing:

- Grant-type-driven session semantics.
- Explicit resource binding.
- Atomic authorization code handling.
- Declarative client policy.

Credenza can serve as a standards-compliant OAuth Authorization Server
while preserving its narrow scope:

- Identity remains upstream.
- Credenza enforces audience boundaries.
- Resource servers enforce business authorization.

These changes enable secure, interoperable deployments in MCP and in
any similar architecture where resource servers must act on behalf of
an authenticated client using OAuth-standard mechanisms.

---

## 3. Decision

Credenza SHALL operate in two clearly separated roles:

1. **OpenID Connect Relying Party (RP)**
2. **Narrow OAuth 2.1 Authorization Server (AS)**

Credenza SHALL:

- Implement the minimum OAuth surface required to issue and validate
  opaque, audience-bound access tokens.
- Delegate identity authentication and user policy evaluation to
  upstream OpenID Providers.
- Avoid implementing consent UI, role engines, or rich authorization
  policy systems.
- Issue only opaque access tokens validated via introspection.
- Enforce audience isolation via resource indicators.
- Require token exchange for cross-resource access.
- Maintain a unified client registry representing all authenticated
  entities requesting session issuance.
- Implement single-use authorization codes with atomic consumption
  guarantees in supported storage backends.

Credenza SHALL NOT:

- Issue JWT access tokens.
- Publish a JWKS endpoint.
- Implement dynamic scope negotiation UI.
- Act as a general-purpose identity provider.
- Implement application-level authorization logic.

---

## 4. Architectural Roles

### 4.1 Credenza as OIDC Relying Party

- Delegates authentication to upstream OpenID Providers.
- Validates ID tokens and identity assertions.
- Establishes internal session records.
- Does not issue ID tokens or act as an OpenID Provider.

---

### 4.2 Credenza as Narrow OAuth Authorization Server

- Issues opaque, audience-bound access tokens.
- Exposes Authorization Code + PKCE flow (OAuth 2.1 profile).
- Supports Device Authorization (RFC 8628).
- Supports Token Introspection (RFC 7662).
- Supports Resource Indicators (RFC 8707).
- Supports Token Exchange (RFC 8693).
- Publishes Authorization Server Metadata (RFC 8414).

`/login` remains a first-party interactive login endpoint and is distinct
from `/authorize`, which implements OAuth 2.1 semantics for registered clients.

---

### 4.3 Unified Client Registry

**Decision:** Credenza SHALL maintain a single declarative client registry
that subsumes legacy OAuth client configuration and `service_auth.json`
M2M bindings.

A **Client** represents any entity capable of authenticating to Credenza
and requesting session issuance.

A client registry entry SHALL define:

- Authentication method (`auth.method`)
- Allowed grant types
- Allowed resource bindings
- Optional redirect URIs (authorization code only)
- Optional scope restrictions
- Optional token exchange permissions
- TTL and lifecycle constraints

Supported authentication methods MAY include:

- `client_secret` (OAuth confidential clients)
- `none` (public clients using PKCE)
- `aws_presigned` (role-based M2M proof)
- Other future proof-context mechanisms (e.g., `mtls`)

Authentication method and grant type are orthogonal:

- Authentication defines how the client proves identity.
- Grant type defines session lifecycle semantics.
- Resource binding defines where the resulting token may be used.

No implicit trust bindings SHALL exist outside the unified registry.

Legacy `service_auth.json` SHALL be deprecated and its semantics
migrated into the unified registry.

---

### 4.4 Authorization Code Infrastructure

Authorization codes SHALL:

- Be short-lived (configurable, typically ~5 minutes).
- Be single-use.
- Be atomically consumed at exchange time.
- Be bound to client_id, redirect_uri, and PKCE challenge at issuance time.

Atomic consumption requirements:

- Redis backend: MUST use `GETDEL`.
- Postgres backend: MUST use `DELETE ... RETURNING`.
- Other backends MAY provide best-effort semantics but are NOT
  recommended for production OAuth usage.

No `used` flag SHALL be relied upon.  
Consumption SHALL be implemented as atomic fetch-and-delete.

PKCE verification:

- `S256` SHALL be required.
- `plain` SHALL NOT be supported.
- PKCE verification SHALL occur during `/token` authorization_code exchange.

---

### 4.5 Session Model

Credenza SHALL represent issued sessions using the following structural invariants:

- `session_type` defines lifecycle semantics and is immutable.
- `allowed_resources` defines audience binding.
- `userinfo` contains canonical identity claims.
- Session expiration and refresh eligibility are determined by grant profile.
- Session expiration is governed by both sliding expiration and absolute lifetime constraints.

Audience enforcement SHALL be applied uniformly based on the
`resource` parameter (RFC 8707), not on legacy session type distinctions.

---

### 4.6 Grant Types & Session Profiles

Credenza supports multiple OAuth grant types.  
Each grant type maps to a distinct **session profile**, defining token lifetime, refresh behavior, and intended use.

---

#### Supported Grant Types

| Grant Type                | RFC                             | Primary Use Case                        | Upstream Refresh | Typical TTL     | Notes                                                                                      |
|---------------------------|---------------------------------|-----------------------------------------|------------------|-----------------|--------------------------------------------------------------------------------------------|
| Authorization Code + PKCE | OAuth 2.1 / RFC 6749 / RFC 7636 | Interactive browser or desktop clients  | No               | Medium          | Sliding expiration via `PUT /session`                                                      |
| Device Authorization      | RFC 8628                        | Headless / CLI clients                  | Yes              | Long            | Bounded by upstream `offline_access` max TTL or service-configured default (e.g., 14 days) |
| Token Exchange            | RFC 8693                        | Audience transformation                 | No               | Short           | Derived, non-transitive                                                                    |
| Service (Proof-Based)     | Internal                        | Machine-to-machine proof-based issuance | No               | Short-to-Medium | Extendable up to configured max TTL                                                        |

Device sessions are intentionally long-lived relative to interactive sessions.  
Their effective maximum lifetime is bounded by upstream refresh expiration
or configured policy (commonly 14 days).

---

#### Session Lifetime Model

Credenza enforces a two-tier expiration model:

1. **Sliding expiration** — Sessions may extend `expires_at` via `PUT /session`
   when permitted by grant profile.
2. **Absolute lifetime cap** — Sessions are bounded by an absolute expiration
   constraint:
   - Service or device sessions: `absolute_expires_at`
   - Interactive sessions: internal TTL policy

Only Device sessions MAY perform upstream token refresh using stored
refresh tokens. Other grant types SHALL NOT perform upstream refresh.

Derived (token exchange) sessions SHALL NOT be extended or refreshed.

---

#### Invariants Across All Grant Types

- All access tokens are **opaque**.
- All access tokens are **audience-bound**.
- All access tokens are validated via **introspection**.
- Resource servers enforce business-level authorization.
- Credenza does not embed application-level authorization logic.

Grant type determines session lifecycle semantics.  
Resource binding determines where a token may be presented.

---

## 5. Token Exchange Policy Constraints

### 5.1 Default-Deny Model

- All token exchange requests are denied unless explicitly allowed.
- No implicit trust relationships exist between resources.

### 5.2 Explicit Resource Allowlist

- Exchange targets MUST be explicitly configured per client.
- Namespace similarity SHALL NOT imply exchange permission.
- Wildcard patterns SHOULD be avoided.

### 5.3 No Automatic Transitivity

- Token exchange SHALL NOT be transitive by default.
- Derived tokens are not automatically eligible for further exchange.

### 5.4 Delegation Policy and Resource Boundaries (Revised 2026-03-19)

The permitted resource set for a token exchange is the intersection of the
client's `allowed_token_exchange_targets` and the client's `allowed_resources`.
The subject token's resource binding is **not** part of this intersection.

**Rationale:** The subject token's bound resources establish *who the user is*
(they authenticated and received a token for resource X). They do not limit
*what downstream resources a trusted intermediary can access on the user's behalf*.
That boundary is enforced by `allowed_token_exchange_targets`, which is
admin-configured and default-deny.

Including the subject resources in the permitted-resource intersection would
break the standard delegated intermediary pattern (RFC 8693 actor/on-behalf-of),
where a user authenticates to a front-end service (e.g., an MCP server scoped
to its own resource URI) that then exchanges the token for access to downstream
services (e.g., DERIVA catalog APIs). The user's front-end token is correctly
scoped to the front-end resource; it would never include the downstream resource
URIs, so the three-way intersection would always be empty.

**What is still prevented:**

- Transitive exchange (section 5.3): derived tokens cannot be exchanged further.
- Target not in `allowed_token_exchange_targets`: denied regardless of subject.
- Target not in `allowed_resources`: denied (client cannot hold that resource token).
- Scope escalation: derived token scopes are bounded by subject session scopes.

**Informed consent implication:** Because a user who authenticates to a delegating
intermediary implicitly authorizes downstream access (without seeing the downstream
resources at authorization time), ADR-0002 introduces an optional consent mechanism
that surfaces `allowed_token_exchange_targets` to the user before the authorization
code is issued. Operators of intermediary clients (e.g., MCP servers) SHOULD
evaluate whether `require_consent: true` is appropriate for their deployment.

### 5.5 Declarative Configuration Only

- Exchange policy MUST remain configuration-driven.
- No embedded policy engine or scripting layer.

### 5.6 Separation of Authorization Responsibilities

- Credenza enforces audience boundaries.
- Resource servers enforce application-level authorization.

### 5.7 Canonical Claim Handling and M2M Assertions (Revised)

**Decision:** Credenza SHALL use `claim_mapper.py` as the single canonical claim normalization layer. All identity-provider attributes and machine-asserted attributes SHALL be normalized into canonical claim keys and stored within `session.userinfo`.

Credenza SHALL NOT introduce a separate protocol-level `"claims"` container. Introspection responses SHALL expose canonical claims as top-level members in accordance with RFC 7662.

---

## 6. Acceptance Criteria

This ADR may move from **Proposed** to **Accepted** when:

1. Authorization Code + PKCE flow is implemented and validated.
2. OAuth metadata endpoint is standards-compliant.
3. Token introspection is implemented and used.
4. Resource indicator enforcement is verified.
5. Token exchange is implemented with:
   - Default-deny policy
   - Explicit allowlist enforcement
   - No transitivity
   - No privilege escalation
6. Unified client registry replaces legacy service bindings.
7. Authorization codes are atomically single-use across supported backends.
8. Security review confirms no unintended IAM expansion.

---

## 7. Consequences

### Positive

- Unified security model
- Elimination of duplicated configuration
- Cleaner authentication abstraction
- Strong audience isolation
- Proper OAuth AS compliance

### Negative

- Larger configuration surface
- Broader security review scope
- Requires careful migration of legacy bindings
- Requires storage backends that support atomic consume for production OAuth use

---

## 8. Alternatives Considered

### 8.1 Upstream IDP as Full Authorization Server

Rejected — breaks opaque token model and couples services to IDP semantics.

### 8.2 Token Passthrough

Rejected — violates audience binding and enables cross-service replay.

### 8.3 Maintain Separate OAuth and M2M Registries

Rejected — duplicates policy and increases inconsistency risk.

---

## 9. Summary

This ADR formalizes Credenza as a narrow OAuth 2.1 Authorization Server
while preserving its core design principle: identity upstream, audience
enforcement in Credenza, and business authorization in resource servers.