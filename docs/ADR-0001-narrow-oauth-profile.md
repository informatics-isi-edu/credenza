# ADR-0001: Credenza as a Narrow OAuth 2.1 Authorization Server and OIDC Relying Party

## 1. Status

**Proposed**\
Decision Date: 2026-02-11

### Review History

| Date       | Status     | Notes                                                              |
|------------|------------|--------------------------------------------------------------------|
| 2026-02-11 | Proposed   | Draft including token exchange constraints and acceptance criteria |
| YYYY-MM-DD | Accepted   | Approved after implementation and security review                  |
| YYYY-MM-DD | Amended    | Updated exchange constraints / clarifications                      |
| YYYY-MM-DD | Superseded | Replaced by ADR-00XX                                               |

## 2. Context

Credenza originally functioned as a session broker in front of upstream
OpenID Connect (OIDC) identity providers. It authenticated users via
OIDC and issued opaque, resource-bound session tokens used by protected
services.

New requirements from OAuth-native resource servers require:

-   OAuth 2.1 Authorization Code + PKCE support
-   RFC 8414 Authorization Server Metadata
-   RFC 7662 Token Introspection
-   RFC 8707 Resource Indicators
-   RFC 8693 Token Exchange
-   Audience-bound access tokens
-   Standards-compliant discovery and validation flows

Credenza must:

-   Remain identity-provider agnostic
-   Avoid duplicating upstream identity policy engines
-   Avoid becoming a full-featured IAM platform
-   Preserve its opaque, resource-bound token model

------------------------------------------------------------------------

## 3. Decision

Credenza SHALL operate in two clearly separated roles:

1.  **OpenID Connect Relying Party (RP)**
2.  **Narrow OAuth 2.1 Authorization Server (AS)**

Credenza SHALL:

-   Implement the minimum OAuth surface required to issue and validate
    opaque, audience-bound access tokens.
-   Delegate identity authentication and user policy evaluation to
    upstream OpenID Providers.
-   Avoid implementing consent UI, role engines, or rich authorization
    policy systems.
-   Issue only opaque access tokens validated via introspection.
-   Enforce audience isolation via resource indicators.
-   Require token exchange for cross-resource access.

Credenza SHALL NOT:

-   Issue JWT access tokens.
-   Publish a JWKS endpoint.
-   Implement dynamic scope negotiation UI.
-   Act as a general-purpose identity provider.
-   Implement application-level authorization logic.

------------------------------------------------------------------------

## 4. Architectural Roles

### 4.1 Credenza as OIDC Relying Party

-   Delegates authentication to upstream OpenID Providers.
-   Validates ID tokens and identity assertions.
-   Establishes internal session records.
-   Does not issue ID tokens or act as an OpenID Provider.

### 4.2 Credenza as Narrow OAuth Authorization Server

-   Issues opaque, audience-bound access tokens.
-   Exposes Authorization Code + PKCE flow (OAuth 2.1 profile).
-   Supports Token Introspection (RFC 7662).
-   Supports Resource Indicators (RFC 8707) for audience-bound access tokens.
-   Supports Token Exchange (RFC 8693).
-   Publishes Authorization Server Metadata (RFC 8414).

## 4.3 Grant Types & Session Profiles

Credenza supports multiple OAuth grant types.  
Each grant type maps to a distinct **session profile**, defining token lifetime, refresh behavior, and intended use.

This ensures predictable security semantics while preserving a narrow Authorization Server scope.

---

### Supported Grant Types

| Grant Type                | RFC                             | Primary Use Case                                       | Refresh Tokens | Typical TTL                                    | Notes                                                  |
|---------------------------|---------------------------------|--------------------------------------------------------|----------------|------------------------------------------------|--------------------------------------------------------|
| Authorization Code + PKCE | OAuth 2.1 / RFC 6749 / RFC 7636 | Interactive browser or desktop clients                 | No             | Medium (e.g., 4–8h)                            | No `offline_access`; fixed session lifetime            |
| Device Authorization      | RFC 8628                        | Headless / CLI clients requiring long-lived API access | Yes            | Short access token (e.g., 30–60m), refreshable | May request `offline_access`; refresh lifetime bounded |
| Token Exchange            | RFC 8693                        | Audience transformation between resource servers       | No             | Short (e.g., 15–30m)                           | Derived tokens; no refresh; non-transitive by default  |

---

### Session Profile Definitions

#### 1. Interactive Session Profile (Authorization Code + PKCE)

- Intended for human-interactive flows.
- No refresh tokens issued.
- No `offline_access` requested from upstream IDP.
- Medium-lived access token.
- Requires full re-authentication upon expiration.
- Suitable for browser sessions and OAuth-native applications.

Security Rationale:
Interactive sessions are expected to be bounded to user work sessions and do not require long-term unattended access.

---

#### 2. Device Session Profile (RFC 8628)

- Intended for headless or CLI-based clients.
- Issues refresh tokens.
- May request `offline_access` from upstream IDP.
- Access tokens are short-lived.
- Refresh token lifetime is bounded by explicit maximum policy.
- Refresh may be revoked centrally.

Security Rationale:
Device flow enables non-browser clients to obtain API access while preserving user-mediated authorization. Refresh capability is necessary for long-running automation but must remain tightly bounded.

---

#### 3. Derived Session Profile (Token Exchange)

- Issued via `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`.
- No refresh tokens issued.
- Short-lived access tokens.
- Non-transitive by default.
- Must not elevate privileges beyond subject session.
- Used exclusively for audience transformation.

Security Rationale:
Derived tokens exist solely to enforce audience isolation. They are intentionally short-lived and non-refreshable to minimize replay and privilege escalation risk.

---

### Invariants Across All Grant Types

Regardless of grant type:

- All access tokens are **opaque**.
- All access tokens are **audience-bound**.
- All access tokens are validated via **introspection**.
- Resource servers enforce business-level authorization.
- Credenza does not embed application-level authorization logic.

---

### Design Constraint

Grant type determines session semantics.

Session lifetime, refresh behavior, and upstream token retention are defined by the grant profile — not by resource type.

This preserves separation of concerns and prevents policy creep.

------------------------------------------------------------------------

## 5. Token Exchange Policy Constraints

### 5.1 Default-Deny Model

-   All token exchange requests are denied unless explicitly allowed.
-   No implicit trust relationships exist between resources.

### 5.2 Explicit Resource Allowlist

-   Exchange targets MUST be explicitly configured per client.
-   Namespace similarity SHALL NOT imply exchange permission.
-   Wildcard patterns SHOULD be avoided.

### 5.3 No Automatic Transitivity

-   Token exchange SHALL NOT be transitive by default.
-   Derived tokens are not automatically eligible for further exchange.
-   Chaining depth MAY be restricted.

### 5.4 No Privilege Escalation via Exchange

-   Exchange SHALL NOT elevate privileges beyond those asserted in the
    subject session.
-   Exchange transforms audience, not authorization scope.

### 5.5 Declarative Configuration Only

-   Exchange policy MUST remain configuration-driven.
-   No embedded policy engine or scripting layer.

### 5.6 Separation of Authorization Responsibilities

-   Credenza enforces audience boundaries.
-   Resource servers enforce application-level authorization.

### 5.7 Canonical Claim Handling and M2M Assertions (Revised)

**Decision:** Credenza SHALL use `claim_mapper.py` as the single canonical claim normalization layer. All identity-provider attributes and machine-asserted attributes SHALL be normalized into canonical claim keys and stored within `session.userinfo`.

Credenza SHALL NOT introduce a separate protocol-level `"claims"` container. Introspection responses SHALL expose canonical claims as top-level members in accordance with RFC 7662.

**Implementation Details:**

- IDP claims are normalized via `resolve_claim()` using the configured claim map.
- Machine-to-machine (M2M) assertions SHALL be inserted into `session.userinfo` under canonical claim keys prior to session persistence.
- No distinction between "idp_claims" and "m2m_claims" SHALL be exposed at the protocol level.
- Introspection SHALL reuse the same claim resolution logic used by `/session`.

**Behavioral Invariants:**

- All claims exposed via introspection are flattened top-level members.
- No nested `"claims"` object SHALL appear in RFC 7662 responses.
- Token exchange SHALL preserve canonical claims unless explicitly configured otherwise.
- M2M assertions MUST NOT overwrite identity-provider canonical claims for overlapping keys.
- `claim_mapper.py` serves as the canonical normalization layer and defines the set of claim keys eligible for exposure via introspection.

**Outcomes:**

- Eliminates semantic ambiguity between IDP claims and M2M assertions.
- Prevents identity forgery semantics previously implied by M2M `groups`.
- Ensures introspection and `/session` remain behaviorally consistent.
- Maintains a narrow OAuth surface without introducing new schema layers.
------------------------------------------------------------------------

## 6. Acceptance Criteria

This ADR may move from **Proposed** to **Accepted** when the following
conditions are met:

1.  Authorization Code + PKCE flow is implemented and validated via
    integration tests.
2.  OAuth metadata endpoint (`/.well-known/oauth-authorization-server`)
    is live and standards-compliant.
3.  Token introspection (`POST /introspect`) is implemented and used by
    at least one resource server.
4.  Resource indicator enforcement is verified in authorization and
    introspection flows.
5.  Token exchange is implemented with:
    -   Default-deny policy
    -   Explicit allowlist enforcement
    -   No automatic transitivity
    -   No privilege escalation
6.  Documentation clearly states scope boundaries and non-goals.
7.  Security review confirms no unintended IAM expansion.

------------------------------------------------------------------------

## 7. Consequences

### Positive

-   Standards-compliant integration with OAuth-native resource servers.
-   Strong audience isolation.
-   Centralized token lifecycle control.
-   Clear identity vs audience authority separation.

### Negative

-   Credenza exposes OAuth endpoints.
-   Requires exchange policy governance.

------------------------------------------------------------------------

## 8. Alternatives Considered

### 8.1 Upstream IDP as Full Authorization Server

Rejected --- breaks opaque token model and tightly couples services to
IDP semantics.

### 8.2 Token Passthrough

Rejected --- violates audience binding and enables cross-service replay.

### 8.3 Expand Credenza into IAM Platform

Rejected --- unnecessary scope expansion.

------------------------------------------------------------------------

## 9. Rationale

Credenza standardizes token issuance and validation while delegating
identity to upstream providers.

Explicit exchange constraints ensure Credenza remains an audience
authority, not an identity authority.

Architectural separation of concerns is preserved:

-   Identity upstream
-   Audience enforcement in Credenza
-   Business authorization in resource servers
