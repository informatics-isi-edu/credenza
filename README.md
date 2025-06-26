# Credenza

### OIDC Relying Party and Session Broker

**Credenza** is a RESTful web service that functions as both an OIDC Relying Party (RP) and a IdP session management and 
brokering layer. It handles OAuth2/OIDC login/logout/device flows to OIDC Operating Parties (OP) and then caches OAuth2 
userinfo, identity claims, tokens and other information provided by Identity Providers to a persistent session storage layer.

#### Features:

- Supports multiple identity providers via OIDC configuration profiles
- Persistent session storage with lifecycle management and optional encryption
- All OAuth2/OIDC flows use `authlib` under-the-hood with PKCE enabled whenever applicable
- Headless login via OAuth2 Device Code Flow
- Background token refresh for device sessions
- Audit logging
- Prometheus metrics

### Project Status

This project is being actively developed and should be considered Alpha quality. It is a functional prototype but is 
also subject to change at any point without notice.