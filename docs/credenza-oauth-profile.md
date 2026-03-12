# Credenza OAuth & OIDC Profile

## Overview

Credenza operates in two distinct but complementary roles:

1.  **OpenID Connect Relying Party (RP)**
2.  **Narrow OAuth 2.1 Authorization Server (AS)**

Credenza delegates user authentication to upstream OpenID Providers
(e.g., Keycloak, Okta, Cognito, Globus) and issues opaque,
audience-bound access tokens for protected resource servers.

Credenza is **not** a general-purpose identity platform or policy
engine. It does not replace upstream identity providers. Instead, it
provides a standards-compliant token authority layer that enables:

-   OAuth-native client integration
-   Audience-bound access control
-   Token introspection
-   Token exchange
-   Identity provider abstraction

This design applies generically to any protected resource server
requiring OAuth-compliant access tokens (e.g., MCP servers, REST APIs,
data platforms, service-to-service endpoints).

------------------------------------------------------------------------

# Architectural Roles

## 1. Credenza as OpenID Connect Relying Party (RP)

In this role, Credenza delegates authentication to upstream OpenID
Providers.

### Standards Implemented

-   **OpenID Connect Core 1.0**
    -   Authorization Code Flow
    -   ID Token validation
    -   State validation
    -   Nonce validation (if used)
    -   UserInfo endpoint consumption (if configured)
-   **RFC 6749 --- OAuth 2.0 (Client Role)**
    -   Authorization code exchange
    -   Confidential client authentication
-   **RFC 8414 --- Authorization Server Metadata**
    -   Consumes upstream discovery documents
-   **RFC 7519 --- JSON Web Token (JWT)**
    -   Validates ID tokens
-   **RFC 7517 --- JSON Web Key (JWK)**
    -   Consumes JWKS for signature verification

### Not Implemented (RP Role)

-   OpenID Provider (OP) functionality
-   ID token issuance
-   Federation services
-   Upstream dynamic client registration

Identity authority remains fully with the upstream provider.

------------------------------------------------------------------------

## 2. Credenza as Narrow OAuth Authorization Server

In this role, Credenza issues and validates opaque, audience-bound
access tokens for protected resource servers.

The architecture is resource-server agnostic and supports any resource
server requiring OAuth-compliant authorization flows, audience isolation,
token introspection, token exchange, or OAuth metadata discovery.

### Standards Implemented

-   **RFC 6749 --- OAuth 2.0 (Authorization Server Role)**
    -   Authorization Code Grant
    -   Client Credentials Grant
-   **RFC 7636 --- PKCE**
    -   `S256` required; `plain` rejected
-   **RFC 8414 --- Authorization Server Metadata**
    -   Discovery endpoint at `/.well-known/oauth-authorization-server`
-   **RFC 7662 --- Token Introspection**
    -   Opaque token validation with per-client resource gating
-   **RFC 8693 --- Token Exchange**
    -   Default-deny exchange policy; confidential client auth required
-   **RFC 8628 --- Device Authorization Grant**
    -   Full spec compliance; client registry enforcement
-   **RFC 7009 --- Token Revocation**
    -   200 on all outcomes; confidential clients authenticate
-   **RFC 8707 --- Resource Indicators**
    -   `resource` parameter on authorization, token, exchange, and introspection requests

### Not Implemented (AS Role)

-   JWT access token issuance
-   JWKS endpoint
-   Dynamic client registration (under consideration)
-   Consent UI or scope negotiation UI

------------------------------------------------------------------------

# OAuth & RFC Compliance (AS Role)

Credenza implements a constrained OAuth 2.1 profile.

------------------------------------------------------------------------

## OAuth 2.1 (draft-ietf-oauth-v2-1)

Supported:

-   Authorization Code Grant
-   PKCE (RFC 7636) --- `S256` required
-   Client Credentials Grant (requires a registered client with `client_credentials` in `allowed_grant_types`)
-   Device Authorization Grant (RFC 8628)
-   Confidential client authentication

Not supported:

-   Implicit Grant
-   Resource Owner Password Grant
-   Refresh tokens for interactive sessions

------------------------------------------------------------------------

## RFC 8414 --- Authorization Server Metadata

Endpoint:

`GET /.well-known/oauth-authorization-server`

Provides:

-   issuer
-   authorization_endpoint
-   token_endpoint
-   introspection_endpoint
-   revocation_endpoint
-   supported grant types
-   supported code challenge methods
-   resource indicator support

------------------------------------------------------------------------

## RFC 7662 --- Token Introspection

Endpoint:

`POST /introspect`

Implements:

-   Opaque token validation
-   Audience validation via `allowed_resources` intersection
-   Per-client resource gating via `allowed_introspection_resources`
-   Standard `active` response semantics
-   Client authentication required

Resource servers validate tokens exclusively through introspection.

------------------------------------------------------------------------

## RFC 8707 --- Resource Indicators

Credenza supports the `resource` parameter on:

-   Authorization requests
-   Token requests
-   Token exchange requests
-   Introspection validation

Access tokens are explicitly bound to resource identifiers, and resource
intersection is enforced during validation.

This prevents cross-service token replay.

------------------------------------------------------------------------

## RFC 8693 --- OAuth 2.0 Token Exchange

Endpoint:

`POST /token` with `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`

Implements:

-   Subject token validation
-   Target resource specification
-   Issuance of new opaque token bound to requested resource
-   Declarative client-level exchange policy
-   Confidential client authentication required

This enables audience transformation without token passthrough.

------------------------------------------------------------------------

## RFC 8628 --- Device Authorization Grant

Endpoints:

`POST /device_authorization` (or `/device/start`)\
`GET /device/verify/<user_code>`\
`POST /token` with `grant_type=urn:ietf:params:oauth:grant-type:device_code`

Implements:

-   RFC 8628 device authorization flow
-   `client_id` required when a client registry is configured
-   Registered clients validated against allowed grant types, scopes, and resources
-   Standard polling error responses (`authorization_pending`, `slow_down`, `expired_token`)
-   PKCE used on the internal browser leg (device-to-IdP redirect)

------------------------------------------------------------------------

## RFC 7009 --- Token Revocation

Endpoint:

`POST /revoke`

Implements:

-   Revocation of opaque session tokens
-   Confidential clients authenticate; public clients provide `client_id`
-   Returns HTTP 200 on all outcomes (including unknown tokens), per RFC 7009

------------------------------------------------------------------------

## OAuth 2.0 Client Authentication (RFC 6749 §2.3)

Supported:

-   `client_secret_basic`
-   `client_secret_post`
-   `none` (public clients; PKCE required for authorization code grant)

Used for:

-   Token exchange
-   Introspection
-   Confidential client code exchange
-   Token revocation

------------------------------------------------------------------------

# Access Token Characteristics

Credenza-issued access tokens are:

-   Opaque
-   Audience-bound
-   Time-limited
-   Stored in Credenza's session store
-   Validated exclusively via introspection

Credenza does not issue JWT access tokens and does not expose a JWKS
endpoint.

------------------------------------------------------------------------

# Explicitly Out of Scope

Credenza does **not** implement:

-   General-purpose identity management
-   Role or attribute-based policy engines
-   Consent UI
-   Scope negotiation UI
-   Fine-grained authorization decisions
-   JWT access tokens
-   Dynamic client registration (not currently implemented; under consideration)

Protected resource servers remain responsible for enforcing
application-level authorization.

# Why This Exists

## The Problem

Modern OAuth-native resource servers require:

-   Authorization Code + PKCE support
-   OAuth discovery
-   Token introspection
-   Audience-bound tokens
-   Token exchange

Upstream identity providers:

-   Authenticate users
-   Issue ID tokens (and sometimes JWT access tokens)
-   Do not provide opaque, resource-scoped tokens aligned with internal
    service boundaries
-   Cannot enforce audience isolation across independently deployed
    services without tight coupling

Directly coupling every resource server to upstream IDPs would:

-   Leak IDP-specific logic into services
-   Complicate revocation semantics
-   Increase cryptographic and operational complexity
-   Make audience isolation inconsistent
-   Reduce architectural flexibility

------------------------------------------------------------------------

## What Credenza Provides

### 1. Audience Isolation

Each access token is bound to a specific resource.\
Tokens cannot be reused across services without explicit exchange.

This prevents cross-service replay.

------------------------------------------------------------------------

### 2. Identity Provider Abstraction

Resource servers integrate only with Credenza introspection.\
Upstream IDPs can change without modifying service integrations.

------------------------------------------------------------------------

### 3. Centralized Token Lifecycle Control

Credenza manages:

-   Token issuance
-   Expiration
-   Revocation
-   Audience binding
-   Exchange policy

This provides operational control without embedding identity logic into
services.

------------------------------------------------------------------------

### 4. Opaque Token Model

Opaque tokens:

-   Avoid claims leakage
-   Allow authoritative revocation
-   Eliminate JWKS rotation complexity
-   Reduce cryptographic surface area
-   Simplify resource server implementations

------------------------------------------------------------------------

### 5. Separation of Concerns

-   Identity authority remains upstream.
-   Credenza enforces audience boundaries.
-   Resource servers enforce business authorization.

Each layer has a single responsibility.

------------------------------------------------------------------------

# Positioning Statement

Credenza operates as an OpenID Connect Relying Party to upstream
identity providers and as a narrow OAuth 2.1 Authorization Server that
issues and validates opaque, audience-bound access tokens.

It provides OAuth standards compliance, audience isolation, and token
lifecycle control without becoming a general-purpose identity or
authorization platform.

Credenza is an audience authority, not an identity authority.
