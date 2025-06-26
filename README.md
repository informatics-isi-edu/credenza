# Credenza

[![CI Status](https://github.com/informatics-isi-edu/credenza/actions/workflows/credenza.yaml/badge.svg)](https://github.com/informatics-isi-edu/credenza/actions)
[![Coverage Status](https://coveralls.io/repos/github/informatics-isi-edu/credenza/badge.svg)](https://coveralls.io/github/informatics-isi-edu/credenza)
[![License](https://img.shields.io/pypi/l/bdbag.svg)](http://www.apache.org/licenses/LICENSE-2.0)

### OIDC Relying Party and Session Broker

**Credenza** is a RESTful web service that functions as both an OIDC Relying Party (RP) and a IdP session management and 
brokering layer. It handles OAuth2/OIDC login/logout/device flows to OIDC Operating Parties (OP) and then caches OIDC 
userinfo, identity claims, tokens and other information provided by Identity Providers to a persistent session storage layer.

#### Features:

- Supports multiple OIDC Operating Parties (OPs) and identity providers (IDPs) via configuration profiles
- Persistent session storage with lifecycle management and session encryption
- All OAuth2/OIDC flows use the Python `authlib` module under-the-hood with PKCE enabled whenever applicable
- Headless login via OAuth2 Device Code Flow
- Secure background token refresh option for device sessions
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

As recent security analyses have highlighted, modernization without coherent identity and session oversight can create more surface area 
for compromise — not less. By providing observability, rotation, and revocation for both user and service tokens, 
Credenza helps bring your authentication layer closer to the operational standards expected in secure, 
federated environments.

#### Further Reading

* [Application identity modernization poses significant risks](https://www.helpnetsecurity.com/2025/05/27/application-identity-modernization-risks/) – Help Net Security 
* [Session Management in Microservices](https://www.geeksforgeeks.org/system-design/session-management-in-microservices) – GeeksforGeeks

### Project Status

This project is being actively developed and should be considered Alpha quality. It is a functional prototype but is 
also subject to change at any point without notice.