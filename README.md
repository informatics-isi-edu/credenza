# Credenza

[![CI Status](https://github.com/informatics-isi-edu/credenza/actions/workflows/credenza.yaml/badge.svg)](https://github.com/informatics-isi-edu/credenza/actions)
[![Coverage Status](https://coveralls.io/repos/github/informatics-isi-edu/credenza/badge.svg)](https://coveralls.io/github/informatics-isi-edu/credenza)
[![License](https://img.shields.io/pypi/l/bdbag.svg)](http://www.apache.org/licenses/LICENSE-2.0)

### OIDC Relying Party and Session Broker

**Credenza** is a RESTful web service that functions as both an OIDC Relying Party (RP) and an IdP session management and
brokering layer. It handles OAuth2/OIDC login/logout/device flows to OIDC Operating Parties (OP) and then caches OIDC
userinfo, identity claims, tokens, and other information provided by Identity Providers to a persistent session storage layer.

Credenza also supports **machine-to-machine (M2M) / service authentication** by issuing **opaque “service access tokens”**
backed by server-side **service sessions**. Service callers prove identity via configured adapters (e.g., AWS STS presigned
GetCallerIdentity), Credenza maps the proof to an internal subject plus authorization envelope (scopes/audiences/groups),
and returns an opaque bearer token for subsequent API calls.

#### Features:

- Supports multiple OIDC Operating Parties (OPs) and identity providers (IDPs) via configuration profiles
- Persistent session storage with lifecycle management and session encryption
- All OAuth2/OIDC flows use the Python `authlib` module under-the-hood with PKCE enabled whenever applicable
- Headless login via OAuth2 Device Code Flow
- Secure background token refresh option for device sessions
- Service Auth / M2M token issuance and revocation
  - Adapter-based proof verification (e.g., AWS presigned STS, client_secret)
  - Opaque bearer tokens backed by server-side `service` sessions (revocable, auditable)
  - Enforcement of allowed **scopes** and **audiences** via configuration
  - Renewal controls (max session TTL clamp, absolute lifetime)
- Audit logging
- Prometheus metrics

### Why Credenza?

Modern applications increasingly delegate authentication to external identity providers using protocols like OIDC,
but often stop short of managing the resulting session lifecycle and token hygiene with equal rigor. This leaves
critical gaps — expired tokens that are still accepted, refresh tokens lingering beyond their intended lifetime, and no
clear view into when or how access was last granted, renewed, or revoked.

**Credenza** fills that void by acting as a lightweight, centralized session broker that maintains consistent access and
refresh token lifecycles across distributed services. It handles token acquisition and refresh delegation, emits structured audit
events, and supports distributed session inspection without exposing sensitive credentials externally.

Credenza extends these guarantees to **service identities** as well: service tokens are **validated by session lookup**
(not self-contained JWTs), enabling **immediate revocation**, consistent renewal semantics, and centralized auditing/rate limiting.

As recent security analyses have highlighted, modernization without coherent identity and session oversight can create more surface area
for compromise — not less. By providing observability, rotation, and revocation for both user and service tokens,
Credenza helps bring your authentication layer closer to the operational standards expected in secure,
federated environments.

#### Further Reading

* [Application identity modernization poses significant risks](https://www.helpnetsecurity.com/2025/05/27/application-identity-modernization-risks/) – Help Net Security
* [Session Management in Microservices](https://www.geeksforgeeks.org/system-design/session-management-in-microservices) – GeeksforGeeks

### Credenza User Authentication Flow
![credenza-flow](./docs/credenza-flow.png)

* #### [Credenza User Auth (OIDC) Documentation](docs/user_auth_oidc.md)

### Credenza Service Authentication (M2M) Flow

- **Issue service token**
  - `POST /authn/service/token` (alias: `POST /authn/service-token`)
  - Requires form field: `grant_type=urn:credenza:service:auth`
  - Adapter-specific proof fields determine which adapter matches
  - Returns: `{"access_token": "<opaque>", "expires_in": <seconds>}`

- **Revoke service token**
  - `DELETE /authn/service/token` (alias: `DELETE /authn/service-token`)
  - Requires: `Authorization: Bearer <access_token>`
  - Only service tokens are revocable here (user sessions use user logout)
  - Returns: `204 No Content`

* #### [Credenza Service Auth (M2M) Documentation](docs/service_auth_m2m.md)

### Project Status

This project is being actively developed and should be considered Alpha quality. It is a functional prototype but is
also subject to change at any point without notice.
