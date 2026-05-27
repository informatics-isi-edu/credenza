# Deployment-Local Identity and Session Brokerage:

## A Technical Pattern for Modern Distributed Systems

## Abstract

Modern distributed systems increasingly rely on external identity providers, standards-based authorization protocols,
and edge authentication components to secure applications and APIs. OpenID Connect, OAuth 2.0, and systems such as
Keycloak, identity-aware proxies, and relying-party middleware have significantly reduced the cost of implementing
federated login and token-based access control. For many deployments, these tools are sufficient.

However, a recurring architectural gap remains between standards-compliant authentication at the edge and the needs of
internal applications and services. Many systems require a deployment-local layer that normalizes identity context
across client types, centralizes session and token policy, brokers downstream credentials, and provides a stable
interface for backends that should not be tightly coupled to external identity infrastructure.

This paper describes that layer as **deployment-local identity and session brokerage**. It explains the problem this
pattern solves, why token validation alone is often insufficient, where standard identity infrastructure ends, and when
a dedicated broker service is justified. It also examines alternative approaches and the tradeoffs among them.

At a high level, the core argument is simple:

- Identity providers and authorization servers solve authentication, federation, and token issuance
- Proxies and relying-party middleware solve edge protection and session establishment
- Backend services still often need a **deployment-local, policy-aware internal abstraction** over identity, session
  state, and downstream credential handling

For simpler systems, this abstraction is unnecessary. For more complex systems, it becomes a useful and recurring
architectural pattern.

---

## Table of Contents

1. Introduction
2. Problem statement
3. The architectural pattern
4. Why token validation alone is often insufficient
5. Why a backend session API can be useful
6. Competing implementation strategies
7. Relationship to identity providers and proxies
8. Why "IAM + Proxy" is often sufficient — and where it stops
9. Downstream and dependent token handling
10. Why this pattern can reduce overall complexity
11. When the pattern is justified
12. When the pattern is not justified
13. Broader industry analogs
14. Conclusion
15. Credenza
16. Comparison tables
17. Decision framework
18. Recommended architectural guidance

---

## 1. Introduction

In the last decade, identity architecture for applications has become increasingly standardized. Instead of bespoke
login systems, deployments now commonly use:

- external or centralized identity providers
- OAuth 2.0 and OpenID Connect
- reverse proxies or relying-party middleware
- JWT-based bearer tokens
- browser, device, and machine-to-machine authorization flows

This shift has been a major improvement. It reduces custom security logic, enables federation across organizations, and
aligns applications with well-understood protocols.

Yet standardization at the protocol layer does not eliminate all identity complexity inside a deployment. In practice,
application ecosystems often need more than:

- "the user is authenticated"
- "the access token is valid"
- "these claims were present in the token"

Instead, they need deployment-specific answers to questions such as:

- What is the normalized principal representation for this system?
- Which services may see raw tokens, and which should see only claims?
- How are browser sessions, device flows, and service credentials represented consistently?
- How are downstream or dependent tokens obtained and cached?
- How are revocation and token freshness enforced across services?
- How are provider-specific claims and token quirks normalized?
- Where do audit, metrics, and security policy live?

Those needs motivate an architectural pattern that is distinct from both an identity provider and a simple relying
party: a **deployment-local identity and session broker**.

---

## 2. Problem Statement

Most identity systems are optimized for one of three layers:

### 2.1 Identity provider / authorization server layer

This layer authenticates users, issues tokens, supports federation, and exposes standards-based endpoints.

### 2.2 Edge protection layer

This layer protects applications at ingress boundaries, establishes sessions, validates or forwards tokens, and passes
identity context downstream.

### 2.3 Application / resource server layer

This layer validates tokens, interprets claims, and makes authorization decisions for business logic.

These layers are necessary, but in many systems they do not fully solve the internal identity-management problem. They
do not automatically provide a **deployment-local control plane for identity and session state** that is usable by
backend services in a uniform way.

The resulting gap often manifests as:

- duplicated JWT-validation logic across services
- inconsistent claim interpretation
- inconsistent audience and resource enforcement
- ad hoc token caching or introspection behavior
- direct service coupling to a particular IdP or broker
- scattered handling of token exchange or dependent tokens
- proxy-centric identity assumptions leaking into internal APIs
- inconsistent audit and observability for identity events

The central problem is not authentication itself. The problem is the absence of a stable, policy-aware, internal
identity abstraction. Many deployments successfully externalize authentication, but do not adequately internalize
identity operations. Each backend service becomes partly responsible for identity translation, policy interpretation,
and token handling — fragmentation that is acceptable at small scale but costly as the system grows.

---

## 3. The Deployment-Local Broker Pattern

A **deployment-local identity and session broker** — referred to throughout as **the broker** — is a service that runs
within a deployment's own trust boundary and provides that deployment's internal applications with a normalized,
policy-aware abstraction over identity, session, and token state.

The *deployment-local* qualifier is deliberate. The broker is not an external SaaS, not the upstream identity provider,
and not an edge proxy. It is a first-party service that the deployment owns and operates, with direct access to
deployment-local configuration, policy, secrets, and storage. Its answers reflect what the deployment knows right now,
not just what the identity provider asserted at login time.

Its purpose is not to replace standards-based identity systems, but to translate them into a deployment-specific
operational model.

Its responsibilities may include:

- normalizing identity across upstream providers and flow types
- representing deployment-local session state
- centralizing token validation and introspection policy
- enforcing token disclosure and redaction rules
- brokering downstream or dependent tokens
- exposing backend-facing identity and session APIs
- applying deployment-specific refresh, revocation, and cache policy
- providing a unified audit and metrics surface for identity operations

This pattern is most useful when identity behavior is no longer just a per-service implementation detail and has instead
become a cross-cutting deployment concern.

The broker is best understood not as a replacement for an identity provider, but as an adaptation layer. It receives
identity artifacts from standards-based systems and translates them into a deployment's internal identity contract —
which may include a normalized subject model, deployment-local session identifiers, service-specific identity views, and
a policy-aware path for downstream token retrieval.

---

## 4. Why Token Validation Alone Is Often Insufficient

A common design assumption is that internal services can simply validate JWTs locally and use claims directly. For
simple systems, that is often correct. If a service only needs to validate a signature, issuer, expiration, and
audience, and then authorize locally from raw claims, a library-based approach can be entirely appropriate.

The difficulty is that real systems often need more:

- claim normalization across multiple IdPs
- distinction between caller-visible claims and broker-visible token state
- centralized handling of token freshness and revocation
- service-specific filtering of identity attributes
- downstream credential retrieval
- coherent behavior across browser, device, and M2M workflows

At that point, identity becomes operational state, not just cryptographic input.

### 4.1 The opaque token advantage

A key design lever is whether access tokens are self-contained JWTs or opaque references to server-side session state.

Self-contained JWTs are convenient for distributed validation — no central call required, low latency. But they also
have inherent limitations: they cannot be revoked without either waiting for expiry or distributing a revocation list,
they carry their full claim payload wherever they are presented, and they cannot be updated after issuance.

Opaque tokens solve these problems. Because they are references to server-side session state, the broker can:

- revoke a session immediately and have that revocation take effect on the next introspection call
- return different claim subsets to different callers at introspection time
- update session metadata without reissuing tokens
- prevent token forwarding to unintended audiences by enforcing audience checks at introspection

The cost is that every token validation requires a call to the broker (or a cached introspection result). For systems
where the broker is the deployment-local control plane anyway, this cost is acceptable and often desirable — it ensures
that the broker, not each individual service, defines what a valid token means at any given moment.

A raw JWT tells a service what the issuer asserted at issuance time. An opaque token validated through the broker tells
a service what the deployment's policy says is true right now.

---

## 5. Why a Backend Session API Can Be Useful

The phrase "backend session API" sometimes sounds like unnecessary indirection. If services can validate tokens, why
would they need an API for identity state?

The answer is that a backend session API is valuable when the deployment wants a **single authoritative internal
contract** for identity-related behavior.

### 5.1 Normalized principal representation

Different providers and flows often produce different claim shapes, naming conventions, and token contents. Backends
benefit from a stable principal model rather than raw upstream variance.

### 5.2 Controlled disclosure

Not every backend should see the same data. Some may need only a stable subject and groups. Others may need richer
claims. A smaller trusted subset may need downstream tokens. Centralizing disclosure policy in a broker is safer than
distributing it across services.

### 5.3 Session-aware behavior

Many deployments care about session metadata not reducible to token claims alone, such as creation time, refresh
history, local revocation state, and deployment-specific security annotations.

### 5.4 Downstream token brokerage

A backend may need a token for another protected service or external API. Rather than forcing every service to implement
exchange, caching, refresh, and provider-specific logic, a broker can centralize that behavior.

### 5.5 Centralized audit and observability

Identity-sensitive events become easier to monitor and govern when they pass through one control-plane service rather
than being embedded in many codebases.

### 5.6 Easier policy rollout

If token acceptance, claim mapping, or disclosure rules change, one service can be updated instead of many applications
and libraries.

A backend session API turns identity from a passive artifact into an active platform capability. Instead of every
service reading identity information differently, services consume a common identity service contract.

---

## 6. Competing Implementation Strategies

There are three broad architectural strategies for backend identity handling.

### 6.1 Strategy A: direct backend token validation

Each backend validates JWTs or introspects opaque tokens and performs authorization locally.

This approach works well when services are simple resource servers, claims are stable and easy to interpret, there is
little need for downstream token handling, and deployment-wide identity policy is minimal.

Its strengths are low latency, no extra service dependency, and straightforward standards alignment. Its weaknesses are
duplicated implementation across services, policy drift, direct coupling between each service and the IdP, and limited
central governance.

### 6.2 Strategy B: shared auth library

A common internal library centralizes token validation, JWKS handling, claim mapping, and perhaps introspection
fallback.

This improves consistency over per-service custom code, but distributes operational identity logic across the fleet. It
becomes harder when multiple languages or frameworks are involved, when token-disclosure policy differs by service, when
token brokerage is needed, and when audit and metrics must be standardized.

### 6.3 Strategy C: deployment-local broker

A dedicated service provides a normalized identity and session contract and centralizes sensitive token behavior.

This approach is strongest when identity behavior is deployment policy, multiple client types exist, downstream token
brokerage is required, and the system wants to reduce application coupling to external identity infrastructure.

Its main cost is the introduction of an additional service boundary.

These strategies are not mutually exclusive. In practice, many deployments combine them — services may validate signed
access tokens locally for request admission while relying on a broker for normalized identity views and downstream token
acquisition.

---

## 7. Relationship to Identity Providers and Proxies

One of the most common sources of confusion is treating identity providers, relying parties, proxies, and session
brokers as interchangeable. They are not.

**Identity providers and authorization servers** authenticate principals, broker upstream identity, issue tokens, and
expose standards-based endpoints.

**Edge proxies and relying-party middleware** protect applications at ingress boundaries, establish sessions, pass
identity downstream, and sometimes handle refresh behavior.

**Deployment-local brokers** provide an internal, backend-facing abstraction over identity, session, and token state.

A deployment-local broker is not an alternative to the first two categories — it complements them. The important
question is not whether one product supports multiple protocols, but whether internal applications can consume all
resulting identities through one stable interface without embedding protocol knowledge.

---

## 8. Why "IAM + Proxy" Is Often Sufficient — and Where It Stops

A full-featured IAM platform such as Keycloak, combined with standards-based relying-party or proxy components such as
`mod_auth_openidc` or `oauth2-proxy`, is often sufficient for deployments whose primary needs are browser login,
federation to external providers, SSO across web applications, basic claim propagation to backends, and standards-based
OAuth and OIDC protocol support.

This should be stated plainly: **many deployments do not need more than that.**

That architecture becomes incomplete, however, when the deployment also needs:

- backend-facing identity and session APIs
- controlled token disclosure to internal services
- deployment-specific session metadata
- downstream or dependent token brokerage
- centralized normalization across browser, device, and service workflows
- insulation of applications from IdP- and proxy-specific behavior
- centralized policy for revocation, refresh, and identity audit

The critical distinction is this: systems like Keycloak solve **protocol and federation** problems well. They do not
automatically solve **deployment-local application-facing unification**. A system may fully support browser flows,
device flows, service accounts, and brokered identities at the protocol layer and still leave backends with no single
internal abstraction over them. Keycloak issues tokens; what internal services do with those tokens — how they
normalize, disclose, cache, exchange, and audit — is left to each service to solve independently.

That is the gap a deployment-local broker addresses.

### 8.1 Introspection alone is not sufficient

Requiring every backend to hold client credentials and introspect tokens is a step toward centralization, but has
important limitations.

Introspection answers whether a token is active and what metadata it currently carries — but it does not provide a
complete deployment-local session model. It also requires every introspecting service to manage confidential client
credentials, spreading secrets and operational responsibility across the fleet. And it adds a synchronous dependency on
the authorization server's availability and latency to the hot path of every request.

Most importantly, each backend still has to decide whether the token is appropriate for it, how to interpret claims, how
to handle disclosure policy, and how to obtain downstream credentials. A broker can make those decisions once,
centrally, rather than distributing them.

Introspection is a powerful mechanism and an important primitive — but it is most effective as one component inside a
larger identity strategy, not as the entire strategy.

---

## 9. Downstream and Dependent Token Handling

One of the clearest justifications for a broker is the need for downstream or dependent tokens.

In multi-service systems, one component often needs to call another protected component or external API. Consider a
concrete example: a user authenticates to a front-end service. That service needs to call a downstream API on the user's
behalf — but with a token scoped to that API's audience, not the original token scoped to the front-end service.
Questions arise immediately:

- Should the original token be forwarded?
- Is a different audience or resource required?
- Should a new delegated or exchanged token be obtained?
- Who may request that token, and under what policy?
- How is it cached, refreshed, and audited?

These concerns are too important and too subtle to leave to ad hoc implementation in every service. RFC 8693 (Token
Exchange) formalizes this pattern at the protocol level, but the policy decisions — which service may exchange tokens
for which audience, what privileges may be delegated, how long derived tokens live — are deployment-specific and belong
in a central policy-aware component.

A broker provides that component. Services that were originally designed only to validate tokens should not also be
responsible for managing credential transformation and delegation. That capability is closer to a token service or
security token service than to a basic application library.

---

## 10. Why This Pattern Can Reduce Overall Complexity

Introducing an additional service may seem like added complexity. But in many cases it reduces **system-wide**
complexity by concentrating the most policy-heavy identity logic in one place.

Without a broker, complexity spreads across IdP configuration, proxy behavior, application code, shared libraries,
service-to-service conventions, token caching rules, and audit implementations. With a broker, applications depend on a
narrower internal contract and remain less coupled to upstream identity details.

Introducing a dedicated control-plane component can reduce aggregate system complexity even while increasing component
count. The key is whether the centralized layer absorbs enough cross-cutting complexity to justify its own existence —
the same reasoning that justifies a shared database, a message bus, or an API gateway.

---

## 11. When the Pattern Is Justified

A deployment-local broker is generally justified when identity handling has become a cross-cutting
platform concern rather than a simple per-service validation task.

Typical indicators:

- multiple client types must be supported consistently (browser, device, CLI, M2M)
- backends require normalized identity and session state
- token disclosure must differ by caller
- downstream or dependent token handling is a first-class requirement
- revocation, cache, or refresh policy must be centralized
- multiple upstream identity sources must be normalized
- audit and observability requirements are strong
- the deployment wants to reduce direct application coupling to external IdPs or proxies

An organizational indicator: when multiple service teams are repeatedly re-solving the same identity problems in
different ways, a broker pattern may be justified even if raw security requirements are not extremely advanced.
Consistency across teams is a legitimate architectural reason.

---

## 12. When the Pattern Is Not Justified

The pattern is often unnecessary when:

- the deployment uses a single, well-understood IdP model
- applications are mainly browser-facing with simple claim needs
- backends are simple resource servers with local authorization
- local JWT validation is sufficient
- downstream token handling is minimal or absent
- policy differences across services are small

In those cases, a library or proxy-based approach is simpler and better.

A deployment-local broker introduces its own operational burden, trust boundary, and failure modes. It should be added
for clear architectural reasons rather than out of abstract preference for centralization.

---

## 13. Broader Industry Analogs

This architectural role overlaps partially with several classes of products: full IAM platforms, token services and
security token services, identity-aware proxies, federated OIDC facades, and API gateway authorization layers.

But most off-the-shelf systems specialize in only part of the problem. Some are strongest at federation and login, some
at edge protection, some at token-service patterns. Fewer provide a full deployment-local backend-facing identity and
session abstraction.

The build-vs-buy question often does not have a clean answer. Many mature products cover pieces of the problem space. A
deployment-specific broker may still be needed to bind those pieces into a cohesive internal model, particularly when
deployment-specific policy and session semantics are non-trivial.

---

## 14. Conclusion

Modern standards and IAM platforms have dramatically improved authentication and authorization architecture. They solve
the hard problems of protocol interoperability, federation, and standards-based token issuance. But they do not
automatically eliminate the internal identity-management problem inside a deployment.

That problem appears when backends need more than valid tokens: they need normalized principals, policy-aware
disclosure, deployment-local session state, downstream credential brokerage, consistent audit, and insulation from
upstream complexity.

A deployment-local broker is a response to that problem. It is not always necessary and should not
be introduced casually. But when identity handling becomes a platform concern rather than a simple resource-server
concern, this pattern provides a coherent and often cleaner solution.

The central design question is not "can the IdP authenticate users?" or "can the proxy protect the app?" The deeper
question is whether internal systems have a stable, policy-aware, deployment-local identity abstraction that meets their
operational needs. Where the answer is no, the broker pattern becomes compelling.

---

## 15. Credenza

Credenza is an implementation of the broker pattern described in this paper. It
functions simultaneously as an OIDC Relying Party — handling login flows to upstream identity providers — and as a
narrow OAuth 2.1 Authorization Server, issuing audience-bound access tokens and providing standards-compliant token
introspection, exchange, and revocation endpoints.

Key design choices that reflect the pattern described here:

**Opaque, server-side tokens.** Credenza issues opaque access tokens backed by server-side sessions rather than
self-contained JWTs. It does not issue refresh tokens; clients do not hold long-lived credentials. This enables
immediate revocation, controlled per-caller disclosure at introspection time, and audience enforcement that
self-contained tokens cannot provide. Sessions can be invalidated instantly; token contents can differ by the resource
server calling introspect.

**Unified session model.** Browser (Authorization Code + PKCE), device (RFC 8628), and M2M service identities (client
credentials) are all represented through one internal session model. Backends interact with a single session API
regardless of how the identity was established. Device sessions are distinct in one respect: they store the upstream
refresh token and perform background token refresh, allowing long-lived device sessions to stay current without user
interaction.

**Token exchange for downstream brokerage.** RFC 8693 token exchange allows services to obtain audience-scoped derived
tokens for downstream APIs, centralizing delegation policy in the broker. Exchange is default-deny; each permitted
exchange target is explicitly configured per client. Derived tokens are short-lived, non-refreshable, and
non-transitive. A concrete example: an MCP server authenticates a user via Authorization Code + PKCE, then exchanges
the resulting session token for a short-lived audience-scoped token to call a downstream data API on the user's behalf
— without the downstream API ever seeing the user's original credentials or the MCP server needing to implement
exchange policy itself.

**Resource-bound audience enforcement.** All tokens are bound to specific resource audiences via RFC 8707 resource
indicators. Cross-service token replay is structurally prevented.

**Per-client introspection gating.** Resource servers are registered clients with explicit policy controlling which
sessions they may introspect. A resource server can only retrieve session claims for tokens scoped to resources it is
authorized to inspect.

**Session augmentation.** Post-authentication providers enrich session state with deployment-specific attributes — group
memberships, GA4GH Passport visas, provider-specific claims — without requiring resource servers to implement that
enrichment themselves.

Credenza is intentionally narrow in scope. It does not implement role engines or rich authorization policy.
Business-level authorization remains in resource servers. An optional consent layer is designed for deployments that
require it: authorization consent for semi-trusted clients, and delegation consent that informs users when a resource
server will be able to impersonate them via token exchange. Credenza's role is the deployment-local control plane for
identity, session, and token lifecycle — absorbing the cross-cutting identity complexity that would otherwise spread
across every service in the deployment.

---

## 16. Comparison Tables

### 16.1 Architectural strategy comparison

| Dimension                   | Direct backend validation | Shared auth library | Deployment-local broker |
|-----------------------------|---------------------------|---------------------|-------------------------|
| Per-request latency         | Lowest                    | Low                 | Moderate                |
| Centralized policy control  | Low                       | Medium              | High                    |
| Service coupling to IdP/AS  | High                      | Medium/High         | Low/Medium              |
| Multi-language consistency  | Low                       | Low/Medium          | High                    |
| Token brokerage support     | Low                       | Medium              | High                    |
| Controlled token disclosure | Low                       | Medium              | High                    |
| Centralized audit/metrics   | Low                       | Medium              | High                    |
| Operational complexity      | Low initially             | Medium              | Medium/High             |
| Long-term fleet consistency | Low                       | Medium              | High                    |

### 16.2 Layer-role comparison

| Layer                      | Primary role                                                  | Typical outputs                                                            | Typical limitations                                                 |
|----------------------------|---------------------------------------------------------------|----------------------------------------------------------------------------|---------------------------------------------------------------------|
| IdP / Authorization Server | Authenticate, federate, issue tokens                          | ID tokens, access tokens, refresh tokens, protocol endpoints               | Does not automatically provide deployment-local backend abstraction |
| Proxy / RP Middleware      | Protect ingress, establish sessions, pass identity downstream | Cookies, headers, proxied identity context                                 | Edge-focused; not a backend identity control plane                  |
| Backend Service            | Validate tokens, authorize requests                           | App-specific authorization decisions                                       | Often forced to absorb identity policy complexity                   |
| Deployment-local Broker    | Normalize identity, manage session state, broker tokens       | Internal session APIs, normalized claims, opaque tokens, downstream tokens | Adds service boundary and operational burden                        |

### 16.3 Fitness-for-purpose comparison

| Scenario                           | Direct validation | Shared library | IAM + proxy | Deployment-local broker |
|------------------------------------|:-----------------:|:--------------:|:-----------:|:-----------------------:|
| Simple APIs with well-scoped JWTs  |    Strong fit     |   Strong fit   |  Optional   |   Usually unnecessary   |
| Browser-only SSO                   |    Weak alone     |   Weak alone   | Strong fit  |        Optional         |
| Multi-client-type ecosystem        |      Limited      |    Moderate    |  Moderate   |       Strong fit        |
| Downstream token brokerage         |       Weak        |    Moderate    |   Partial   |       Strong fit        |
| Strict per-caller disclosure rules |       Weak        |    Moderate    |   Limited   |       Strong fit        |
| Immediate revocation requirement   |   Not possible    |  Not possible  |   Limited   |       Strong fit        |
| Internal identity/session API      |       Weak        |    Moderate    |   Limited   |       Strong fit        |

Note on IAM + proxy fitness: full IAM platforms have good protocol coverage for browser, device, and service account
flows. The "Partial" and "Limited" ratings reflect their application-facing internal abstraction, not their protocol
capabilities. The distinction is whether backends have a stable unified session contract, not whether the platform
supports the relevant OAuth flows.

---

## 17. Decision Framework

### 17.1 Start with the simplest sufficient model

Begin with the assumption that local validation, a shared library, or an IdP-plus-proxy model may be enough.

### 17.2 Ask the key architectural questions

1. Do backend services need more than token validity and raw claims?
2. Do multiple services need a normalized principal and session view?
3. Do different internal callers need different visibility into claims or tokens?
4. Is downstream or dependent token handling a first-class requirement?
5. Do browser, device, CLI, and service identities need to be unified operationally?
6. Is immediate revocation required?
7. Is centralized audit and observability for identity operations important?
8. Would direct service coupling to the IdP or proxy layer create long-term fragility?
9. Are multiple teams already re-implementing identity policy inconsistently?

### 17.3 Interpret the answers

- If most answers are **no**, a broker is likely unnecessary.
- If a few answers are **yes**, a shared library may be the right next step.
- If many answers are **yes** — especially around downstream credentials, disclosure policy, normalized session state,
  and revocation — a deployment-local broker is likely justified.

### 17.4 Use escalation, not default complexity

The broker pattern should be introduced when needed, not by default. But once needed, it should be recognized as a
first-class architecture rather than an ad hoc exception.

---

## 18. Recommended Architectural Guidance

### 18.1 Prefer direct validation for simple resource servers

If services only need local authorization based on well-scoped JWT claims, keep the architecture simple.

### 18.2 Use a shared library when consistency is needed but policy remains simple

If multiple services share the same runtime and auth logic, a library can reduce duplication without introducing a new
service.

### 18.3 Use a broker when identity becomes platform state

If identity handling involves policy, disclosure, brokerage, normalization, and audit concerns spanning many services,
use a deployment-local broker.

### 18.4 Do not confuse protocol coverage with application-facing unification

An IdP that supports many OAuth and OIDC flows still may not provide the internal abstraction that applications need.

### 18.5 Centralize high-sensitivity token operations

Downstream token issuance, exchange, refresh, and disclosure should live in a smaller, more governable trust boundary
than "every backend."

### 18.6 Design the broker as a complement to standards, not a replacement

The strongest deployment-local brokers do not compete with standards-based IAM. They absorb deployment-specific
semantics that standards-based systems intentionally leave open.

---

*For extended design considerations, appendices on lifecycle differences, token validation primitives, backend API
patterns, trust-boundary and threat-model notes, and a glossary,
see [whitepaper-technical-annex.md](whitepaper-technical-annex.md).*