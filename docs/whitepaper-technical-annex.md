# Deployment-Local Identity and Session Brokerage: Technical Annex

This annex accompanies [whitepaper.md](whitepaper.md) and contains extended design considerations, implementation patterns, and reference material.

---

## A. Lifecycle Differences Across Client Types

Different client types produce different operational identity lifecycles, and a broker's value in unifying them is significant.

### A.1 Browser-based sessions
These are often ingress-mediated, cookie-backed, and refresh-capable. The edge may hold important session state that is not visible to backend services unless exposed through a normalized internal layer. Browser sessions typically have sliding expiration extended by user activity.

### A.2 Device flows
These introduce delayed authorization and polling behavior (RFC 8628). The resulting identity may be authenticated by the same upstream IdP, but operationally it has a different lifecycle than a browser session: the authorization is asynchronous and the token is typically longer-lived. Device sessions are usually intended for headless or CLI clients that cannot complete a browser redirect. Unlike browser sessions, device sessions store the upstream refresh token in the broker and perform background token refresh, allowing them to stay current without user interaction. This is the one grant type for which the broker holds and uses a long-lived upstream credential on the user's behalf.

### A.3 CLI and headless clients
These may behave like device flows, direct token consumers, or service-like clients depending on architecture. Their identity often requires explicit local modeling to avoid being treated as either a browser session or a full service account.

### A.4 Service accounts and machine-to-machine flows
These are client-centric rather than user-session-centric — the principal is a service identity rather than a human. They still often need to be represented consistently alongside user-derived identities for backend authorization and audit. The client credentials grant is the typical mechanism.

One value of a broker is that these heterogeneous lifecycles map into one normalized internal model. A backend service does not need to know whether it is processing a browser session, a device token, or an M2M service credential — it consumes a session with a stable structure.

---

## B. Token Validation, Introspection, and Token Exchange

These three concepts are often conflated but address different problems.

### B.1 Token validation
Validation determines whether a presented token is structurally and semantically acceptable for a given service. For JWTs this typically means: verify the signature against the issuer's JWKS, check `exp`, `iss`, and `aud` claims, and read the payload. For opaque tokens it means calling an introspection endpoint — local validation is not possible.

The key limitation of JWT self-validation is that it reflects the state at issuance, not at validation time. A JWT cannot be revoked without waiting for expiry or maintaining and distributing a revocation list. A broker issuing opaque tokens can revoke sessions immediately.

### B.2 Introspection
Introspection (RFC 7662) asks an authorization server whether a token is currently active and retrieves its current metadata. It is the primary validation mechanism for opaque tokens. Unlike JWT self-validation, introspection reflects current state — a revoked session returns `active: false` immediately.

Introspection pushes a synchronous dependency on the AS into the request path. Caching introspection results reduces latency at the cost of some staleness. The appropriate cache TTL depends on revocation requirements: shorter TTLs allow faster revocation propagation; longer TTLs reduce AS load.

Resource servers calling introspect should hold registered client credentials to identify themselves. This allows the AS to enforce per-caller disclosure policy — returning different claim subsets to different resource servers based on their registration.

### B.3 Token exchange and downstream credential issuance
RFC 8693 (Token Exchange) formalizes the pattern of obtaining a new token scoped to a different audience or resource, typically to call a downstream service on behalf of the original subject. It addresses a different problem from simple token validation.

Key design constraints for secure token exchange:
- default-deny: exchange should be prohibited unless explicitly permitted
- no transitive exchange: a derived token should not itself be exchangeable
- no privilege escalation: the derived token cannot grant access beyond what the original session allows
- short lifetime: derived tokens should be short-lived and non-refreshable
- audit: each exchange should produce an audit event

Architectures often need all three primitives, but they should not be mistaken for one another.

---

## C. Backend Session API Design Patterns

Several patterns recur in broker implementations.

### C.1 "Current principal" endpoint
Returns the normalized caller identity suitable for ordinary backend use. This is typically the most-called endpoint and should be optimized for latency via caching.

### C.2 Redacted versus privileged identity views
Ordinary services receive minimal claims — subject, groups, basic attributes. Privileged services can request richer detail under explicit policy. This differentiation is critical: not every backend should see raw upstream tokens, downstream credentials, or sensitive identity attributes.

### C.3 Brokered downstream-token endpoint
Allows approved callers to request tokens for specific target services without directly implementing exchange logic. The broker enforces the allowlist, issues a scoped derived token, and logs the exchange. Callers should not need to understand RFC 8693 internals.

### C.4 Session metadata endpoint
Returns deployment-local session state beyond raw token claims: creation time, last activity, grant type, realm, refresh history, and deployment-specific annotations.

### C.5 Revocation and admin endpoints
Support operational review, session termination, and traceability. These endpoints are high-sensitivity and should require strong authentication and authorization to access.

These APIs should be designed conservatively. Overly broad identity APIs can become internal attack surfaces.

---

## D. Trust-Boundary and Threat-Model Considerations

A broker improves architectural clarity only if it is properly secured.

### D.1 The broker is a high-value target
Because the broker holds session state, refresh tokens, and downstream credentials, it is a higher-value target than an ordinary backend. It should be treated as a security-sensitive infrastructure component with correspondingly strong controls: network isolation, strong client authentication for all callers, strict logging, and careful secret management.

### D.2 Token disclosure policy
The broker should implement explicit disclosure policy controlling which callers can retrieve which claims. At minimum, resource servers should be registered and authenticated before introspecting. Sensitive claims — raw upstream tokens, downstream credentials, security-relevant metadata — should not be returned to general-purpose callers.

### D.3 Downstream token handling
Refresh tokens and downstream credentials stored in the broker should be encrypted at rest. Their use should be logged. Their lifetime should be bounded by configuration.

### D.4 Replay and misuse protections
Authorization codes and one-time credentials should be atomically consumed to prevent replay. Token exchange should be idempotent with appropriate rate limiting. JTI caches should be maintained for assertion-based auth methods.

### D.5 Revocation propagation
Immediate revocation is only as strong as introspection cache TTLs allow. Deployments with strong revocation requirements should use short cache TTLs or push-based revocation notification.

### D.6 Failure modes
Designers must decide what happens when the broker is unavailable:
- fail closed: reject all requests (maximum security, maximum disruption)
- fail open for previously cached results: use bounded-staleness caches
- allow local validation for admission but disable downstream token operations
- each service handles broker unavailability independently

The right choice depends on the deployment's availability versus security requirements.

---

## E. Operational Tradeoffs

The broker pattern introduces both benefits and costs that should be explicitly weighed.

### Benefits
- centralized policy rollout: one service to update when token acceptance, claim mapping, or disclosure rules change
- stronger observability: all identity-sensitive events pass through one audit surface
- reduced application coupling: services depend on an internal contract, not on IdP-specific behavior
- less duplicated sensitive token logic: exchange, refresh, and downstream credential handling live in one place
- more consistent identity semantics across services, teams, and languages

### Costs
- additional service to operate, monitor, and maintain
- another high-value security component requiring careful hardening
- potential latency increase for broker-mediated operations (mitigated by caching)
- cache and revocation TTL tradeoffs require operational discipline
- strong internal authorization design required to prevent the broker from becoming an over-privileged internal surface
- single point of failure risk if not deployed with appropriate redundancy

A deployment should explicitly weigh these factors rather than assuming centralization is automatically beneficial. The broker pattern is a commitment.

---

## F. Extended Design Considerations

### F.1 Data model

Common internal objects in a broker implementation:

- **principal**: the normalized representation of an authenticated entity (user or service)
- **session**: the lifecycle container for an authentication event, including grant type, expiry, and metadata
- **credential set**: the upstream tokens (access, refresh, ID) associated with a session
- **downstream token cache**: scoped tokens obtained for target services, keyed by session and target
- **policy annotations**: deployment-specific attributes attached to a session (allowed resources, security tier, etc.)
- **audit event**: structured record of identity-sensitive operations

### F.2 API surface

Typical internal APIs:

- resolve current principal and normalized claims
- fetch redacted or privileged identity view
- obtain downstream token for a target service
- inspect or update session metadata
- revoke or disable session
- admin search and audit interfaces

### F.3 Caching strategy

Caches improve performance but complicate revocation and freshness semantics. The broker is the right place to standardize those tradeoffs. Typical cache layers:

- introspection result cache (short TTL, per token)
- JWKS cache (longer TTL, per issuer)
- downstream token cache (TTL bounded by token expiry)
- rate-limit state (window-bounded, per principal or IP)

### F.4 Storage backend considerations

For production deployments supporting OAuth flows, storage backends must provide:

- **atomic consume** for authorization codes and one-time credentials (Redis `GETDEL`, PostgreSQL `DELETE ... RETURNING`)
- **shared state** across workers for rate limiting, JTI replay prevention, and revocation
- **encryption at rest** for sessions containing upstream tokens

In-memory backends are appropriate for development and single-worker testing but should not be used in production multi-worker deployments where atomicity and cross-worker consistency matter.

---

## G. Glossary

**Authorization Server:** A system that issues tokens and exposes OAuth-related endpoints (RFC 6749).

**Identity Provider:** A system that authenticates users and provides identity assertions, typically via OIDC.

**Relying Party:** An application or intermediary that delegates authentication to an IdP and consumes the resulting tokens or assertions.

**Identity-aware proxy:** A front-door component that protects upstream applications and injects identity context derived from session or token validation.

**Resource Server:** A service that accepts and authorizes API requests based on access tokens.

**Deployment-local broker:** A first-party service that runs within a deployment's own trust boundary and provides that deployment's internal applications with a normalized, policy-aware abstraction over identity, session, and token state. Unlike an external SaaS or upstream identity provider, it is owned and operated by the deployment, with direct access to deployment-local configuration, policy, secrets, and storage. Its answers reflect current deployment policy, not just what the identity provider asserted at login time.

**Opaque token:** An access token that is a reference to server-side state rather than a self-contained, self-verifiable artifact. Requires introspection for validation.

**Dependent token:** A downstream token obtained for a target service or API rather than directly presented by the original caller. Distinguished from the subject token used to obtain it.

**Session metadata:** Deployment-local identity and session state that is not reducible to raw token claims alone.

**Token exchange (RFC 8693):** An OAuth grant type that allows a client to obtain a new token with a different audience, scope, or subject, subject to policy.

**Resource indicator (RFC 8707):** A parameter in OAuth requests identifying the specific resource server for which a token is being requested, enabling audience-bound token issuance.

**PKCE (RFC 7636):** Proof Key for Code Exchange. A mechanism that binds an authorization code to the client that initiated the request, preventing code interception attacks. Required for public clients in OAuth 2.1.