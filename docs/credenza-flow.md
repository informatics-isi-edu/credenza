# Credenza Authentication Flows

<!-- --8<-- [start:flow-overview] -->
## Component Overview

```mermaid
flowchart TB
    subgraph clients["Clients"]
        direction TB
        BC["Browser Client"]
        DC["Device / CLI Client"]
        MC["M2M Service"]
        RS["Resource Server"]
    end

    subgraph cred["Credenza"]
        direction TB
        AZ["/authorize"]
        LG["/login (legacy)"]
        CB["/callback"]
        TK["/token"]
        DV["/device_authorization"]
        IN["/introspect (RFC 7662)"]
        SE["/session"]
    end

    IDP(["External OIDC Provider\nKeycloak / RAS / Globus\n Okta / Cognito / etc"])
    SS[(\nSession Storage\nRedis / PostgreSQL)]

    clients --> cred
    cred --> IDP
    cred --> SS
```
<!-- --8<-- [end:flow-overview] -->

---

<!-- --8<-- [start:flow-authcode] -->
## Flow 1: Authorization Code + PKCE

Used by OAuth-registered clients (e.g. MCP). No session cookie is set.

```mermaid
sequenceDiagram
    participant BC as Browser Client
    participant AZ as Credenza /authorize
    participant IDP as External IDP
    participant CB as Credenza /callback
    participant TK as Credenza /token
    participant SS as Session Storage

    BC->>AZ: GET /authorize (client_id, PKCE, scope, resource)
    AZ->>IDP: redirect to IDP login
    IDP-->>CB: auth code (via redirect)
    CB->>SS: create session, store auth code
    CB-->>BC: redirect to redirect_uri with auth code
    BC->>TK: POST /token (code, code_verifier)
    TK->>SS: consume auth code (atomic), verify PKCE
    TK-->>BC: opaque access token (= session key)
```
<!-- --8<-- [end:flow-authcode] -->

---

<!-- --8<-- [start:flow-device] -->
## Flow 2: Device Authorization Grant (RFC 8628)

Used by CLI tools and headless clients.

```mermaid
sequenceDiagram
    participant DC as Device / CLI Client
    participant DV as Credenza /device_authorization
    participant User as User (browser)
    participant TK as Credenza /token
    participant SS as Session Storage

    DC->>DV: POST /device_authorization (client_id, scope, resource)
    DV-->>DC: device_code, user_code, verification_uri
    DC->>DC: display user_code + verification_uri to user

    loop poll every interval
        DC->>TK: POST /token (device_code)
        alt user has not yet authorized
            TK-->>DC: 400 authorization_pending
        else interval too fast
            TK-->>DC: 429 slow_down
        else user authorized
            TK->>SS: create DEVICE session
            TK-->>DC: opaque access token
        end
    end

    Note over User: user visits verification_uri, enters user_code, logs in via IDP
```
<!-- --8<-- [end:flow-device] -->

---

<!-- --8<-- [start:flow-m2m] -->
## Flow 3: Client Credentials (M2M)

Used by backend services authenticating directly with a client secret.

```mermaid
sequenceDiagram
    participant MC as M2M Service
    participant TK as Credenza /token
    participant SS as Session Storage

    MC->>TK: POST /token (client_credentials, client_id, client_secret, resource)
    TK->>SS: create SERVICE session
    TK-->>MC: opaque access token
```
<!-- --8<-- [end:flow-m2m] -->

---

<!-- --8<-- [start:flow-legacy] -->
## Flow 4: Legacy Browser Login

Pre-OAuth flow; still supported. Sets a session cookie instead of issuing an OAuth token.

```mermaid
sequenceDiagram
    participant BC as Browser Client
    participant LG as Credenza /login
    participant IDP as External IDP
    participant CB as Credenza /callback
    participant SS as Session Storage

    BC->>LG: POST /login
    LG->>IDP: redirect to IDP login
    IDP-->>CB: tokens + claims (via redirect)
    CB->>SS: create session
    CB-->>BC: Set-Cookie: session key (httponly, secure)
```
<!-- --8<-- [end:flow-legacy] -->

---

<!-- --8<-- [start:flow-introspect] -->
## Flow 5: Resource Server -- Token Introspection (RFC 7662)

Resource servers call this to validate an opaque token and retrieve claims.

```mermaid
sequenceDiagram
    participant RS as Resource Server
    participant IN as Credenza /introspect
    participant SS as Session Storage

    RS->>IN: POST /introspect (token, client_id + secret)
    IN->>SS: lookup session by token
    alt token active
        IN-->>RS: active=true, claims, scope, resource (filtered per client policy)
    else token missing or expired
        IN-->>RS: active=false
    end
```
<!-- --8<-- [end:flow-introspect] -->

---

<!-- --8<-- [start:flow-exchange] -->
## Flow 6: Resource Server -- Token Exchange (RFC 8693)

A resource server exchanges a user token for a short-lived derived token scoped to a downstream service.

```mermaid
sequenceDiagram
    participant RS as Resource Server
    participant TK as Credenza /token
    participant SS as Session Storage

    RS->>TK: POST /token (token_exchange, subject_token, resource, client_id + secret)
    TK->>SS: validate subject token (active, resource-bound)
    TK->>TK: check exchange policy (default-deny allowlist, no escalation)
    TK->>SS: create DERIVED session (30 min cap, non-refreshable)
    TK-->>RS: short-lived derived token
```
<!-- --8<-- [end:flow-exchange] -->

---

<!-- --8<-- [start:flow-session] -->
## Flow 7: Session Inspection

```mermaid
sequenceDiagram
    participant BC as Browser Client
    participant SE as Credenza /session
    participant SS as Session Storage

    BC->>SE: GET /session (cookie or bearer token)
    SE->>SS: lookup session
    SE-->>BC: session attributes, scopes, identity claims
```
<!-- --8<-- [end:flow-session] -->