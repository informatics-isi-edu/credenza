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
[![CI Status](https://github.com/informatics-isi-edu/credenza/actions/workflows/credenza.yaml/badge.svg)](https://github.com/informatics-isi-edu/credenza/actions)
[![Coverage Status](https://coveralls.io/repos/github/informatics-isi-edu/credenza/badge.svg)](https://coveralls.io/github/informatics-isi-edu/credenza)
[![License](https://img.shields.io/pypi/l/bdbag.svg)](http://www.apache.org/licenses/LICENSE-2.0)

This project is being actively developed and should be considered Alpha quality. It is a functional prototype but is 
also subject to change at any point without notice.