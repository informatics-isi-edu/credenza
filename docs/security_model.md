# Credenza Security Model

## Overview

Credenza operates as:

-   An **OpenID Connect Relying Party (RP)** to upstream identity
    providers.
-   A **narrow OAuth 2.1 Authorization Server (AS)** issuing opaque,
    audience-bound access tokens.

Credenza is not a general-purpose identity provider, policy engine, or
authorization platform. It enforces audience isolation and token
lifecycle control while delegating identity authentication and user
policy to upstream OpenID Providers.

This document describes the security boundaries, assumptions, and
operational controls for Credenza.

------------------------------------------------------------------------

# Security Architecture

## Trust Boundaries

| Component          | Responsibility                                      |
|--------------------|-----------------------------------------------------|
| Upstream IDP       | User authentication, MFA, identity assurance        |
| Credenza (RP role) | ID token validation, session establishment          |
| Credenza (AS role) | Token issuance, introspection, audience enforcement |
| Resource Servers   | Application-level authorization                     |

Credenza enforces **audience boundaries** but does not make fine-grained
business authorization decisions.

------------------------------------------------------------------------

# Threat Model

## 1. Token Replay Across Services

### Risk

An access token intended for one resource server is replayed against
another.

### Mitigation

-   All access tokens are **audience-bound** (RFC 8707).
-   Resource intersection validation occurs during introspection.
-   Token exchange (RFC 8693) is required for audience transformation.
-   No token passthrough between services.

------------------------------------------------------------------------

## 2. Token Theft

### Risk

An attacker obtains a bearer token and attempts unauthorized use.

### Mitigation

-   Opaque tokens (no embedded claims).
-   Short to medium TTLs.
-   Derived tokens have shorter TTLs than primary sessions.
-   Introspection required for validation.
-   Revocation enforced centrally.

Operational recommendations:

-   TLS required for all endpoints.
-   Avoid logging full tokens.
-   Rotate client secrets periodically.

------------------------------------------------------------------------

## 3. Unauthorized Token Exchange

### Risk

A confidential client attempts to mint tokens for unauthorized
resources.

### Mitigation

-   Client authentication required (`client_secret_basic` or
    `client_secret_post`).
-   Declarative `allowed_token_exchange_targets` configuration (RFC 8693).
-   Default-deny exchange policy.
-   Structured audit logging of exchange attempts.

------------------------------------------------------------------------

## 4. Introspection Endpoint Abuse

### Risk

High-rate introspection or unauthorized introspection.

### Mitigation

-   Client authentication required for introspection (RFC 7662).
-   `allowed_introspection_resources` per-client gating: a client may only introspect tokens that carry at least one matching resource, preventing cross-service token inspection.
-   Rate limiting recommended.
-   Callers (resource servers) should cache positive introspection results short-term to reduce load.
-   Monitoring for anomalous traffic patterns.

------------------------------------------------------------------------

## 5. Upstream IDP Compromise

### Risk

Upstream IDP issues compromised or malicious identity assertions.

### Mitigation

-   ID token signature validation.
-   Issuer validation.
-   Audience validation.
-   Expiration enforcement.
-   Nonce and state validation during login.

Credenza assumes upstream IDPs are trusted identity authorities.

------------------------------------------------------------------------

## 6. Misconfiguration of Resource Patterns

### Risk

Overly broad resource matching allows unintended token issuance.

### Mitigation

-   Explicit resource identifiers required.
-   Avoid wildcard patterns where possible.
-   Validate configuration at startup.
-   Audit exchange policy changes.

------------------------------------------------------------------------

# Token Design Principles

Credenza-issued access tokens are:

-   Opaque
-   Audience-bound
-   Time-limited
-   Validated via introspection
-   Centrally revocable

Credenza does **not**:

-   Issue JWT access tokens
-   Publish a JWKS endpoint
-   Expose token contents to clients
-   Perform claim transformation

------------------------------------------------------------------------

# Deployment Model & Operational Assumptions

## Enclave-Oriented Deployment

Credenza is intended to operate **within a single trust domain (enclave)** such as:

- A Kubernetes cluster  
- A VPC  
- A namespace or isolated network segment  
- A single environment (e.g., `dev`, `staging`, `prod`)  

Each Credenza instance should broker authentication only for applications and services that reside within that same trust boundary.

Credenza **is not** designed to be a **global, multi-tenant authentication provider** spanning unrelated deployments or organizations.

Credenza **is** designed as an **internal authentication broker for a single trust domain**.
Operate it per-enclave, keep it isolated, validate configuration strictly, and avoid turning it into a global authentication authority unless you are prepared to implement full multi-tenant security architecture.

---

## Core Assumptions

### 1. Single Administrative Tenant

- Each Credenza instance serves one administrative boundary.
- Client registry and adapter configuration are operator-controlled and local to that deployment.

### 2. Network Isolation/Exposure (Allowed, But Controlled)

Credenza may be:

- Publicly reachable (e.g., for user-agent flows)
- Accessible by clients outside the immediate enclave

OAuth endpoints such as `/authorize`, `/token`, and `/device_authorization` must be reachable by clients.

However:

- Deployment should still follow standard best practices (TLS termination, load balancers, reverse proxies).
- Backend storage systems (Redis, Postgres) should remain internal.
- Operational controls (rate limiting, logging, monitoring) should be enforced.

Isolation refers to **logical trust boundaries**, not necessarily private network placement.

### 3. Scoped Resource Identifiers

Resource identifiers may be:

- URNs (logical scoping), or  
- HTTPS URIs (network-scoped resources).  

Network URIs must use `https` only -- `http://localhost` or `http://127.0.0.1` may be permitted only for explicit development environments.

### 4. Static, Operator-Controlled Registry

- Client registry is versioned configuration.
- Values (hosts, URLs) are templated at deploy time.
- Registry validation occurs at startup and must fail fast on invalid entries.

---

## Why This Model

### Security

- Limits blast radius of token compromise.
- Prevents accidental cross-environment privilege sharing.
- Avoids complex cross-tenant policy enforcement.

### Simplicity

- No multi-tenant routing logic.
- No cross-deployment resource resolution.
- No need for dynamic tenant discovery or federation mechanisms.

### Operational Clarity

- Tokens issued by a Credenza instance are meaningful only within that enclave.
- Clear trust boundaries simplify auditing and debugging.

---

## What This Model Avoids

Credenza should not:

- Issue tokens intended for arbitrary external deployments.
- Act as a centralized global identity authority for unrelated environments.
- Share resource namespaces across independent infrastructure domains.

If those capabilities are required, a different architecture (explicit federation, tenant isolation layers, stronger namespace enforcement) must be introduced.

---

## Recommended Operational Controls

- Enforce HTTPS for all network resource URIs.
- Store secrets in enclave-specific secret stores.
- Rotate credentials regularly.
- Log token issuance and session lifecycle events.
- Validate registry configuration at startup.
- Restrict backend storage access (Redis/Postgres) to internal networks only.


------------------------------------------------------------------------

# Security Assumptions

Credenza assumes:

1.  Upstream IDPs correctly authenticate users.
2.  Resource servers enforce their own application-level authorization.
3.  All communications occur over TLS.
4.  Client secrets are protected.

------------------------------------------------------------------------

# Reporting Security Issues

If you discover a vulnerability in Credenza:

-   Do not open a public issue.
-   Contact the maintainers privately at: **isrd-support@isi.edu**
-   Provide:
    -   Description of the issue
    -   Steps to reproduce
    -   Impact assessment
    -   Suggested remediation (if known)

We will acknowledge receipt within 5 business days and coordinate
responsible disclosure.

------------------------------------------------------------------------

# Security Philosophy

Credenza's security philosophy is:

-   **Minimal surface area**
-   **Clear responsibility boundaries**
-   **Audience isolation by default**
-   **Centralized token lifecycle control**
-   **Standards-compliant, but narrowly scoped OAuth implementation**

Credenza is an audience authority, not an identity authority.
