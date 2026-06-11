# Credenza + NIH RAS: OIDC Authentication Flows

**Purpose.** This document describes, in implementation-level detail, how Credenza
authenticates users against the NIH Research Authorization Service (RAS) / NIH Login
identity provider, for two distinct client experiences:

1. **Browser flow** -- OAuth 2.1 Authorization Code with PKCE, for interactive web clients.
2. **Device flow** -- OAuth 2.0 Device Authorization Grant (RFC 8628), for CLIs, headless
   tools, and input-constrained devices.

It is written to illustrate Credenza's compliance and compatibility with the NIH RAS
OpenID Provider (OP): PKCE, single-use authorization codes with atomic consumption,
assurance-level (IAL2 / AAL2) enforcement, nonce binding, and the handling of
RAS-specific claims (`federated_identities_ial2`).

> **Environment: RAS STAGING only.** Every flow, configuration value, and captured
> example in this document was produced and verified against RAS **staging**
> (`stsstg.nih.gov`). RAS **production** (`sts.nih.gov`) has **not** been tested. Endpoints,
> assurance URIs, claim shapes, and especially refresh-token behavior (Sec. 4.3) may differ in
> production and must be re-validated there before any production reliance.

---

## 1. Roles and trust planes

Credenza sits between the client and RAS and plays **two roles simultaneously**. It is
critical to distinguish the two planes, because PKCE, codes, state, and nonce exist
*independently* on each:

```mermaid
flowchart LR
    C["Client<br/>(browser / device)"]
    Z["Credenza<br/>(AS + RP broker)"]
    R["RAS<br/>(NIH Login OP)"]

    C -->|"/authorize, then /token"| Z
    Z -.->|"redirect + code, then session token"| C
    Z ==>|"upstream /authorize, then /token"| R
    R -.->|"code, then id_token"| Z
```

- **Downstream plane** (`C <-> Z`): Credenza is the OAuth 2.1 Authorization Server / broker.
- **Upstream plane** (`Z <-> R`): Credenza is the OIDC Relying Party to RAS.

Credenza spans both planes. PKCE, authorization codes, `state`, and `nonce` exist
*independently* on each.

| Plane          | Credenza role                    | Peer                | Auth-code                              | PKCE                                                                 | nonce / state                                               |
|----------------|----------------------------------|---------------------|----------------------------------------|----------------------------------------------------------------------|-------------------------------------------------------------|
| **Downstream** | Authorization Server (OAuth 2.1) | Client app / device | Credenza-issued, single-use, 5 min TTL | Client supplies `code_challenge` (S256); required for public clients | client `state` echoed back                                  |
| **Upstream**   | OIDC Relying Party               | RAS OP              | RAS-issued, exchanged once by Credenza | Credenza generates `code_verifier` per login                         | Credenza generates `nonce` + `state`, validates in ID token |

The bearer token Credenza ultimately returns to the client is an **opaque Credenza
session key**, never the RAS access/ID token. RAS tokens are held server-side in the
session record. This is the core brokering property: downstream resource servers
introspect Credenza, not RAS.

---

## 2. RAS realm configuration

The upstream relationship is declared as a realm in `oidc_idp_profiles.json`. The live
`nih-ras` profile:

```json
{
  "nih-ras": {
    "discovery_url": "https://stsstg.nih.gov/.well-known/openid-configuration",
    "userinfo_url": "https://stsstg.nih.gov/openid/connect/v1.1/userinfo",
    "logout_url": "https://authtest.nih.gov/siteminderagent/smlogout.asp",
    "scopes": "openid email profile federated_identities_ial2",
    "scope_expected_claims": {
      "profile": ["name", "preferred_username", "federated_identities_ial2"]
    },
    "request_offline_access_scope_in_device_flow": false,
    "skip_token_revocation": true,
    "required_acr": [
      "https://stsstg.nih.gov/assurance/aal/2",
      "https://stsstg.nih.gov/assurance/ial/2"
    ],
    "session_augmentation_provider": "credenza.api.session.augmentation.ras_provider:RasSessionAugmentationProvider",
    "client_secret_file": "secrets/ras_client_secret.json"
  }
}
```

| Setting                                                 | Compliance / compatibility role                                                                                                                                                                                                                    |
|---------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `discovery_url`                                         | RFC 8414 / OIDC Discovery. Credenza fetches the RAS `authorization_endpoint`, `token_endpoint`, `jwks_uri`, etc. at startup; no endpoints are hardcoded.                                                                                           |
| `scopes`                                                | Requested upstream scope set. `federated_identities_ial2` triggers RAS to return IAL2-verified linked identities.                                                                                                                                  |
| `scope_expected_claims`                                 | Declares which claims each scope must yield. Drives the **userinfo fallback** (Sec. 3.3): if the ID token omits `federated_identities_ial2`, Credenza fetches it from the RAS `userinfo_url`.                                                      |
| `required_acr`                                          | **Assurance enforcement.** Login is rejected unless the ID token `acr` claim contains *all* listed URIs (AAL2 **and** IAL2).                                                                                                                       |
| `request_offline_access_scope_in_device_flow` = `false` | Credenza does not append the `offline_access` *scope* upstream. RAS keys refresh-token issuance off the `access_type=offline` parameter (still sent in the device flow), not this scope, so device sessions do receive a refresh token (Sec. 4.3). |
| `skip_token_revocation` = `true`                        | On logout Credenza does not call an upstream RFC 7009 revocation endpoint (RAS STS does not expose a standard one); local session deletion is authoritative.                                                                                       |
| `userinfo_url`                                          | Explicit RAS UserInfo endpoint used for the claims fallback.                                                                                                                                                                                       |
| `session_augmentation_provider`                         | `RasSessionAugmentationProvider` -- exposes `build_identities()` to canonicalize `federated_identities_ial2` into the session's `identities` view (Sec. 6).                                                                                        |

---

## 3. Flow A -- Browser Authorization Code + PKCE

### 3.1 Sequence

```mermaid
sequenceDiagram
    autonumber
    participant C as Client (browser)
    participant Z as Credenza (AS + RP)
    participant R as RAS (NIH Login OP)

    C->>Z: GET /authorize?client_id&redirect_uri&response_type=code<br/>&code_challenge&code_challenge_method=S256&scope&state
    Note over Z: Validate client_id, redirect_uri (exact match),<br/>response_type, PKCE (S256), scope, resource
    Z->>Z: Store authn_request_ctx(oidc_state) incl. client PKCE challenge,<br/>generate upstream nonce + code_verifier
    Z-->>C: 302 -> RAS authorization_endpoint (upstream PKCE)
    C->>R: GET RAS /authorize (with Credenza's code_challenge, state, nonce)
    Note over R: User authenticates at NIH Login (AAL2 / IAL2)
    R-->>C: 302 -> Credenza /callback?code=RAS_CODE & state=OIDC_STATE
    C->>Z: GET /callback?code&state
    Z->>R: POST RAS /token (code + Credenza code_verifier)
    R-->>Z: id_token, access_token (+ userinfo claims)
    Z->>Z: Validate id_token signature + nonce
    Z->>Z: Enforce required_acr (AAL2 + IAL2), userinfo fallback if claims missing
    Z->>Z: Create USER session, mint single-use auth code (5 min TTL)
    Z-->>C: 302 -> client redirect_uri?code=CREDENZA_CODE & state
    C->>Z: POST /token grant_type=authorization_code<br/>(code, redirect_uri, code_verifier)
    Note over Z: Atomically CONSUME code (replay-proof),<br/>verify client_id, redirect_uri, PKCE
    Z-->>C: returns opaque session key as access_token (token_type bearer, expires_in)
    C->>Z: GET /session  (Authorization: Bearer SESSION_KEY)
    Z-->>C: session document (identities, scopes, ...)
```

### 3.2 Step 1 -- `GET /authorize` (downstream, Credenza as AS)

Validated strictly before any redirect (`rest/authorize.py`):

- `client_id` -- must exist and be enabled in the client registry (else `400`/`401`, **no
  redirect**, because the `redirect_uri` is not yet trusted).
- `redirect_uri` -- must **exactly** match a registered `allowed_redirect_uris` entry.
- `response_type` -- must be `code`.
- **PKCE** -- `code_challenge` is **required for public clients**; `code_challenge_method`
  must be `S256` (the `plain` method is rejected for everyone).
- `scope` / `resource` -- must be within the client's `allowed_scopes` / `allowed_resources`.

After validation, Credenza opens the **upstream** leg to RAS via
`create_authorization_url(use_pkce=True, state=oidc_state, nonce=...)`, generating its own
upstream `code_verifier` and `nonce`. All cross-leg state is stashed in a transient
`authn_request_ctx` keyed by the upstream `oidc_state`:

```text
authn_request_ctx[oidc_state] = {
  nonce, code_verifier, scope, realm, redirect_uri (=/callback),
  oauth_client_id, oauth_redirect_uri, oauth_state,
  oauth_scope, oauth_resources,
  oauth_code_challenge, oauth_code_challenge_method,   # the CLIENT's PKCE challenge
  oauth_session_ttl
}
```

The client's PKCE challenge is carried here and later copied into the issued code payload --
it is verified at `/token` time, not now.

### 3.3 Step 2 -- `GET /callback` (upstream, Credenza as RP)

RAS redirects back with its authorization code. Credenza
(`rest/login.py`):

1. Looks up `authn_request_ctx` by `state`.
2. Exchanges the RAS code at the RAS token endpoint, presenting the **upstream**
   `code_verifier` (PKCE on the Credenza<->RAS leg).
3. Validates the RAS **ID token signature** and the **nonce** binding.
4. **ACR enforcement** -- `check_acr(userinfo, required_acr)` returns any missing assurance
   URIs; a non-empty result yields `403 Insufficient authentication assurance level`.
   For `nih-ras` this requires both `.../assurance/aal/2` and `.../assurance/ial/2`.
5. **UserInfo fallback** -- `get_missing_scope_claims()` checks the ID token against
   `scope_expected_claims`. If `federated_identities_ial2` is absent, Credenza calls the
   RAS `userinfo_url` (bearer = RAS access token) and merges the result.
6. Creates a `SessionType.USER` session holding the RAS tokens + userinfo, bound to the
   `oauth_resources` / `oauth_session_ttl` from the original `/authorize`.

### 3.4 Step 3 -- single-use authorization code issuance

Credenza mints its **own** downstream authorization code (distinct from the RAS code):

```text
auth_code = token_urlsafe(32)
set_authorization_code(auth_code, {
   session_id, client_id, redirect_uri,
   code_challenge, code_challenge_method,   # the CLIENT's PKCE challenge
   scope, resources, realm, issued_at
}, ttl = 300)                               # 5 minutes
```

It then 302-redirects to the client's `redirect_uri` with `code` and the echoed client
`state`. (If the client requires consent, an ADR-0002 consent interstitial is inserted
first; the code is issued only after approval.)

### 3.5 Step 4 -- `POST /token` (`grant_type=authorization_code`)

`_handle_authorization_code_grant` (`rest/token.py`) performs, in order:

1. **Atomic consume** -- `consume_authorization_code(code)` is a single read-and-delete.
   The code is destroyed on first use; a replay returns `invalid_grant`. Atomicity is
   backend-enforced: `GETDEL` (Redis/Valkey), `DELETE ... RETURNING` (PostgreSQL/SQLite),
   in-process for Memory. **Any** subsequent validation failure still leaves the code
   consumed -- there is no retry; the `/authorize` request must be restarted.
2. `client_id` must equal the value recorded at `/authorize`.
3. `redirect_uri` must match **exactly** (RFC 6749 Sec. 4.1.3).
4. **PKCE verification** -- when a `code_challenge` was stored, `code_verifier` is required
   and checked with `verify_pkce(challenge, verifier, "S256")`; failure -> `invalid_grant`.
5. The session created at `/callback` is retrieved and its **opaque session key** is
   returned as the bearer token:

```json
{
  "access_token": "<opaque-credenza-session-key>",
  "token_type": "bearer",
  "expires_in": 3600
}
```

No new session is created at `/token`; the code is simply a single-use claim ticket for
the session minted during `/callback`.

### 3.6 `GET /session` excerpt (browser / USER session)

> _`GET /session` response for a `nih-ras` USER session._

```json
{
  "client": {
    "id": "https://stsstg.nih.gov/EXAMPLE-RAS-SUBJECT-0000",
    "display_name": "00000000-0000-0000-0000-000000000000@login.gov",
    "full_name": "FAKEY MCFAKERSON",
    "email": "fakey.mcfakerson@gmail.com",
    "identities": [
      "00000000-0000-0000-0000-000000000000@login.gov"
    ]
  },
  "attributes": [
    {
      "id": "https://stsstg.nih.gov/EXAMPLE-RAS-SUBJECT-0000",
      "display_name": "00000000-0000-0000-0000-000000000000@login.gov",
      "full_name": "FAKEY MCFAKERSON",
      "email": "fakey.mcfakerson@gmail.com",
      "identities": [
        "00000000-0000-0000-0000-000000000000@login.gov"
      ]
    }
  ],
  "since": "2026-06-11T05:06:32+00:00",
  "expires": "2026-06-11T06:06:32+00:00",
  "seconds_remaining": 3583
}
```

---

## 4. Flow B -- Device Authorization Grant (RFC 8628)

For CLIs and headless/input-constrained clients. Credenza implements the full RFC 8628
device grant on top of the same upstream RAS OIDC login.

### 4.1 Sequence

```mermaid
sequenceDiagram
    autonumber
    participant D as Device / CLI
    participant U as User's browser
    participant Z as Credenza (AS + RP)
    participant R as RAS (NIH Login OP)

    D->>Z: POST /device_authorization (client_id, scope, resource)
    Z-->>D: returns device_code, user_code, verification_uri, interval, expires_in
    Note over D: Display user_code + verification_uri,<br/>begin polling /token
    U->>Z: GET /device/verify/USER_CODE
    Z->>Z: consume_usercode_mapping(user_code) -> device_code (single-use)
    Z->>Z: generate upstream nonce + code_verifier (PKCE)
    Z-->>U: 302 -> RAS authorization_endpoint
    U->>R: Authenticate at NIH Login (AAL2 / IAL2)
    R-->>U: 302 -> Credenza /device/callback?code&state=DEVICE_CODE
    U->>Z: GET /device/callback
    Z->>R: POST RAS /token (code + code_verifier)
    R-->>Z: id_token, access_token
    Z->>Z: Validate id_token + nonce, enforce required_acr, userinfo fallback
    Z->>Z: Create DEVICE session, mark flow verified
    Z-->>U: "Device Authorized" page
    loop until verified or expired
        D->>Z: POST /token grant_type=device_code (device_code, client_id)
        alt pending
            Z-->>D: 400 authorization_pending
        else too fast
            Z-->>D: 429 slow_down
        else verified
            Z-->>D: returns session key as access_token (token_type, expires_in)
        end
    end
```

### 4.2 Step 1 -- `POST /device_authorization` (alias `/device/start`)

`start_device_flow` (`rest/device.py`). RFC 8628 compliance points:

- `client_id` is **required** when a client registry is configured; unknown/disabled
  clients are rejected (`401`) unless `ALLOW_UNREGISTERED_CLIENTS` is set.
- For registered clients, the `device_code` grant must be in `allowed_grant_types`, and
  requested `scope` / `resource` are validated against the client's allowlists; confidential
  clients must authenticate.
- High-entropy identifiers: `device_code` = 128-bit (`token_hex(16)`), `user_code` =
  32-bit uppercase hex.
- The flow record and the `user_code -> device_code` mapping are stored with a common TTL
  (default 600 s).

Response:

```json
{
  "device_code": "<128-bit hex>",
  "user_code": "<8 hex chars>",
  "verification_uri": "${BASE_URL}/device/verify/<user_code>",
  "interval": 3,
  "expires_in": 600
}
```

### 4.3 Step 2 -- user verification + upstream RAS login

The user opens `verification_uri`. `verify_device`:

- **single-use** consumes the `user_code -> device_code` mapping
  (`consume_usercode_mapping`); a second use of the same `user_code` returns `404`.
- Starts the upstream RAS login with PKCE
  (`create_authorization_url(use_pkce=True, access_type="offline")`), storing the upstream
  `nonce` + `code_verifier` on the device-flow record. The `device_code` itself is used as
  the upstream `state`.
- Because `request_offline_access_scope_in_device_flow=false` for `nih-ras`, the
  `offline_access` **scope** is not appended upstream. The request is still made with
  `access_type=offline`, which is the mechanism RAS actually keys refresh-token issuance
  off of (see the note below).

`device_callback` then mirrors the browser callback: RAS code exchange (with PKCE),
ID-token + nonce validation, **`required_acr` enforcement (AAL2 + IAL2)**, userinfo
fallback for `federated_identities_ial2`, and creation of a `SessionType.DEVICE` session.
The flow is marked `verified` with the session key attached, and the PKCE verifier / nonce
are cleared from the record.

> **Refresh tokens.** RAS issues a refresh token in response to `access_type=offline` on
> the authorization request -- **not** in response to the `offline_access` scope. Because
> the device flow passes `access_type=offline` (above), RAS returns a refresh token and the
> DEVICE session is marked `offline_access_granted=true` and is refreshable. RAS does not
> assert a refresh-token lifetime -- its token response carries **no** refresh-token expiry
> field at all (only the 30-minute access-token `expires_in`/`expires_at`) -- so Credenza
> applies the `MAX_REFRESH_TOKEN_LIFETIME` default (14 days) as the absolute session
> lifetime. The real RAS refresh expiry is therefore server-side and opaque to Credenza.
> (The browser flow in Sec. 3 does **not** pass `access_type=offline`, so interactive USER
> sessions are not issued a refresh token and follow the interactive TTL policy.)
>
> _This refresh-token behavior is confirmed against RAS **staging** (`stsstg.nih.gov`);
> production (`sts.nih.gov`) behavior should be validated before relying on it there._

**Background refresh and dead-grant eviction.** A per-process background worker
(`refresh/refresh_worker.py`) keeps DEVICE-session access tokens fresh by exchanging the
stored refresh token as it nears expiry; RAS rotates the refresh token on each use and
Credenza persists the rotated value. If a refresh fails, the worker tracks consecutive
failures on the session and **stops retrying** rather than hammering RAS indefinitely: it
evicts the session immediately on a terminal OAuth error (`invalid_grant`, `invalid_client`,
`unauthorized_client`) or after `MAX_REFRESH_FAILURES` (default 5) consecutive failures of
any kind, emitting a `session_evicted_refresh_failures` audit event. The user must then
re-authenticate. 

### 4.4 Step 3 -- `POST /token` (`grant_type=urn:ietf:params:oauth:grant-type:device_code`)

`_handle_device_code_grant` (`rest/token.py`) -- RFC 8628 Sec. 3.5 polling semantics:

| Condition                                                  | Response                          |
|------------------------------------------------------------|-----------------------------------|
| `device_code` unknown / expired                            | `400 expired_token`               |
| `client_id` != the one recorded at `/device_authorization` | `400 invalid_grant`               |
| Polled faster than `interval`                              | `429 slow_down`                   |
| Not yet `verified`                                         | `400 authorization_pending`       |
| Verified, session live                                     | `200` with the opaque session key |

On success the device flow record is deleted and the session key is returned:

```json
{
  "access_token": "<opaque-credenza-session-key>",
  "token_type": "bearer",
  "expires_in": 1209600
}
```

### 4.5 `GET /session` excerpt (device / DEVICE session)

> _`GET /session` response for a `nih-ras` DEVICE session._

```json
{
  "client": {
    "id": "https://stsstg.nih.gov/EXAMPLE-RAS-SUBJECT-0000",
    "display_name": "00000000-0000-0000-0000-000000000000@login.gov",
    "full_name": "FAKEY MCFAKERSON",
    "email": "fakey.mcfakerson@gmail.com",
    "identities": [
      "00000000-0000-0000-0000-000000000000@login.gov"
    ]
  },
  "attributes": [
    {
      "id": "https://stsstg.nih.gov/EXAMPLE-RAS-SUBJECT-0000",
      "display_name": "00000000-0000-0000-0000-000000000000@login.gov",
      "full_name": "FAKEY MCFAKERSON",
      "email": "fakey.mcfakerson@gmail.com",
      "identities": [
        "00000000-0000-0000-0000-000000000000@login.gov"
      ]
    }
  ],
  "since": "2026-06-11T04:08:43+00:00",
  "expires": "2026-06-25T04:08:43+00:00",
  "seconds_remaining": 1206231
}
```

---

## 5. Session storage representation

Both flows persist a server-side session record (encrypted at rest, AES-GCM) keyed by the
opaque session key. It holds the RAS tokens, the raw RAS userinfo (including
`federated_identities_ial2`), the realm, session type, allowed resources, and lifetime
metadata.

> _Stored session payload (decrypted view) -- this capture is the **DEVICE** session from Sec. 4
> (note `_session_type: "device"`, the `refresh_token`, and `offline_access_granted: true`).
> A browser USER session (Sec. 3) has the same shape but no `refresh_token` and
> `offline_access_granted: false`._

```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ik5JSC1BVVRILUdMT0JBTC1TSUdOLVNURy0wMk5PVjIxIn0.eyJpc3MiOiJodHRwczovL3N0c3N0Zy5uaWguZ292IiwiaWF0IjoxNzgxMTUyNDYxLCJhdWQiOiIxMTExMTExMS0xMTExLTExMTEtMTExMS0xMTExMTExMTExMTEiLCJleHAiOjE3ODExNTQyNjEsInNjb3BlIjoib3BlbmlkIGVtYWlsIHByb2ZpbGUgZmVkZXJhdGVkX2lkZW50aXRpZXNfaWFsMiIsImp0aSI6IkVYQU1QTEUtSlRJLTAwMDAiLCJ0eG4iOiJFWEFNUExFLVRYTi0wMDAwIn0.SIGNATURE-REMOVED-FOR-PUBLICATION-not-a-valid-jwt-signature",
  "userinfo": {
    "sub": "EXAMPLE-RAS-SUBJECT-0000",
    "aud": "11111111-1111-1111-1111-111111111111",
    "c_hash": "EXAMPLE-CHASH-0000",
    "acr": "https://stsstg.nih.gov/assurance/aal/2 https://stsstg.nih.gov/assurance/ial/2",
    "azp": "11111111-1111-1111-1111-111111111111",
    "auth_time": 1781150921,
    "iss": "https://stsstg.nih.gov",
    "exp": 1782446921,
    "iat": 1781150921,
    "nonce": "EXAMPLE-NONCE-0000",
    "name": "FAKEY MCFAKERSON",
    "first_name": "FAKEY",
    "last_name": "MCFAKERSON",
    "preferred_username": "00000000-0000-0000-0000-000000000000@login.gov",
    "userid": "00000000-0000-0000-0000-000000000000",
    "email": "fakey.mcfakerson@gmail.com",
    "federated_identities_ial2": {
      "default_identity": "00000000-0000-0000-0000-000000000000@login.gov",
      "authenticated_identity": "00000000-0000-0000-0000-000000000000@login.gov",
      "sources": {
        "login.gov": {
          "identity_username": "00000000-0000-0000-0000-000000000000@login.gov",
          "ial": 2,
          "identity_sub": "EXAMPLE-RAS-SUBJECT-0000"
        }
      },
      "identities": {
        "login.gov": {
          "mail": "fakey.mcfakerson@gmail.com",
          "userid": "00000000-0000-0000-0000-000000000000",
          "firstname": "FAKEY",
          "lastname": "MCFAKERSON"
        }
      }
    }
  },
  "created_at": 1781150923,
  "updated_at": 1781152462,
  "expires_at": 1782360523,
  "realm": "nih-ras",
  "_session_type": "device",
  "_allowed_resources": [
    "urn:deriva:rest:service:all"
  ],
  "id_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ik5JSC1BVVRILUdMT0JBTC1TSUdOLVNURy0wMk5PVjIxIn0.eyJzdWIiOiJFWEFNUExFLVJBUy1TVUJKRUNULTAwMDAiLCJhdWQiOiIxMTExMTExMS0xMTExLTExMTEtMTExMS0xMTExMTExMTExMTEiLCJjX2hhc2giOiJFWEFNUExFLUNIQVNILTAwMDAiLCJhY3IiOiJodHRwczovL3N0c3N0Zy5uaWguZ292L2Fzc3VyYW5jZS9hYWwvMiBodHRwczovL3N0c3N0Zy5uaWguZ292L2Fzc3VyYW5jZS9pYWwvMiIsImF6cCI6IjExMTExMTExLTExMTEtMTExMS0xMTExLTExMTExMTExMTExMSIsImF1dGhfdGltZSI6MTc4MTE1MDkyMSwiaXNzIjoiaHR0cHM6Ly9zdHNzdGcubmloLmdvdiIsImV4cCI6MTc4MjQ0NjkyMSwiaWF0IjoxNzgxMTUwOTIxLCJub25jZSI6IkVYQU1QTEUtTk9OQ0UtMDAwMCJ9.SIGNATURE-REMOVED-FOR-PUBLICATION-not-a-valid-jwt-signature",
  "refresh_token": "22222222-2222-2222-2222-222222222222",
  "scopes": "openid email profile federated_identities_ial2",
  "session_ttl": 3600,
  "absolute_expires_at": 1782360523,
  "session_metadata": {
    "system": {
      "allow_automatic_refresh": true,
      "offline_access_granted": true,
      "access_token_expires_at": 1781154262,
      "refresh_token_expires_at": 1782360523
    },
    "user": {}
  },
  "additional_tokens": {}
}
```

---

## 6. RAS claim handling -- `federated_identities_ial2`

RAS returns the user's IAL2-verified linked identities under `federated_identities_ial2`,
split across parallel `sources` (OIDC subject + assurance) and `identities` (profile
detail) sub-blocks, keyed by source provider (e.g. `login.gov`):

> _Raw `federated_identities_ial2` claim as returned by RAS._

```json
{
  "federated_identities_ial2": {
    "default_identity": "00000000-0000-0000-0000-000000000000@login.gov",
    "authenticated_identity": "00000000-0000-0000-0000-000000000000@login.gov",
    "sources": {
      "login.gov": {
        "identity_username": "00000000-0000-0000-0000-000000000000@login.gov",
        "ial": 2,
        "identity_sub": "EXAMPLE-RAS-SUBJECT-0000"
      }
    },
    "identities": {
      "login.gov": {
        "mail": "fakey.mcfakerson@gmail.com",
        "userid": "00000000-0000-0000-0000-000000000000",
        "firstname": "FAKEY",
        "lastname": "MCFAKERSON"
      }
    }
  }
}
```

`RasSessionAugmentationProvider.build_identities()` canonicalizes this **at render time**
(a pure transform of stored claims; nothing extra is persisted) into a map keyed by the
identity id (`sources[src].identity_username`, matching RAS's own
`default_identity` / `authenticated_identity` handle):

> _Canonicalized `identities` (modern `/session` view), keyed by `identity_username`._

```json
{
  "identities": {
    "00000000-0000-0000-0000-000000000000@login.gov": {
      "iss": "login.gov",
      "provider": "login.gov",
      "sub": "EXAMPLE-RAS-SUBJECT-0000",
      "ial": 2,
      "email": "fakey.mcfakerson@gmail.com",
      "userid": "00000000-0000-0000-0000-000000000000",
      "name": "FAKEY MCFAKERSON"
    }
  }
}
```

The legacy/webauthn-compatible `/session` view exposes the identity ids as a flat list
(`identities` keys) by default; the full detail map is available via the modern response
or the `LEGACY_IDENTITY_DETAIL` opt-in.

---

## 7. Compliance / compatibility matrix

| Requirement                                                     | Mechanism in Credenza                                                                                                                                  | Reference                                         |
|-----------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------|
| OIDC Discovery (no hardcoded endpoints)                         | RAS `discovery_url` fetched at startup                                                                                                                 | `oidc_idp_profiles.json`                          |
| PKCE on the RP<->OP leg                                         | `create_authorization_url(use_pkce=True)`; `code_verifier` per login                                                                                   | `rest/authorize.py`, `rest/device.py`             |
| PKCE on the client<->AS leg (S256, required for public clients) | `/authorize` validation + `verify_pkce` at `/token`                                                                                                    | `rest/authorize.py`, `rest/token.py`              |
| Single-use authorization codes                                  | `set_authorization_code(ttl=300)` + atomic `consume_authorization_code`                                                                                | `rest/login.py`, `session_store.py`               |
| Replay protection (read-and-delete)                             | `GETDEL` / `DELETE ... RETURNING` per backend                                                                                                          | `storage/backends/*`                              |
| Nonce binding                                                   | generated per login, validated in `validate_id_token`                                                                                                  | `rest/login.py`, `rest/device.py`                 |
| Assurance enforcement (IAL2 + AAL2)                             | `required_acr` + `check_acr`; `403` on shortfall                                                                                                       | `api/common/util.py`                              |
| Exact redirect-URI matching                                     | `allowed_redirect_uris` at `/authorize`; re-checked at `/token`                                                                                        | `rest/authorize.py`, `rest/token.py`              |
| RAS identity claims                                             | `federated_identities_ial2` scope + UserInfo fallback + `RasSessionAugmentationProvider`                                                               | `ras_provider.py`                                 |
| Device grant (RFC 8628)                                         | `device_code`/`user_code`, `interval`, `slow_down`, `authorization_pending`, `expired_token`                                                           | `rest/device.py`, `rest/token.py`                 |
| No upstream token leakage                                       | downstream bearer = opaque Credenza session key                                                                                                        | `rest/token.py`                                   |
| Token revocation peculiarity                                    | `skip_token_revocation` (RAS has no standard RFC 7009 endpoint)                                                                                        | `oidc_idp_profiles.json`                          |
| Refresh rotation + dead-grant eviction                          | rotated refresh token persisted each cycle; worker evicts on terminal OAuth error or after `MAX_REFRESH_FAILURES` (`session_evicted_refresh_failures`) | `refresh/refresh_worker.py`, `api/common/util.py` |

---

## 8. Endpoint reference

| Endpoint                                  | Method  | Plane      | Purpose                                                                     |
|-------------------------------------------|---------|------------|-----------------------------------------------------------------------------|
| `/.well-known/oauth-authorization-server` | GET     | Downstream | RFC 8414 AS metadata                                                        |
| `/authorize`                              | GET     | Downstream | OAuth 2.1 Authorization Code + PKCE                                         |
| `/callback`                               | GET     | Upstream   | RAS OIDC redirect handler (browser)                                         |
| `/token`                                  | POST    | Downstream | `authorization_code`, `device_code`, `token-exchange`, `client_credentials` |
| `/device_authorization` (`/device/start`) | POST    | Downstream | RFC 8628 device authorization request                                       |
| `/device/verify/{user_code}`              | GET     | Upstream   | User verification -> RAS login                                              |
| `/device/callback`                        | GET     | Upstream   | RAS OIDC redirect handler (device)                                          |
| `/session`                                | GET/PUT | Downstream | Session introspection / extension                                           |
| `/introspect`                             | POST    | Downstream | RFC 7662 token introspection (resource servers)                             |
| `/logout`                                 | GET     | Downstream | Session termination                                                         |

