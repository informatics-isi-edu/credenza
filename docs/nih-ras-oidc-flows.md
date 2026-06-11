# Credenza + NIH RAS: OIDC Authentication Flows

**Purpose.** This document describes, in implementation-level detail, how Credenza
authenticates users against the NIH Research Authorization Service (RAS) / NIH Login
identity provider, for two distinct client experiences:

1. **Browser sign-in** -- two variants over the same upstream RAS login: a legacy
   session-cookie login for webauthn consumers (the path under active test, Sec. 3 A1) and
   an OAuth 2.1 Authorization Code + PKCE flow for OAuth-native clients (Sec. 3 A2).
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

> **Terminology -- "webauthn".** Throughout this document, *webauthn* refers to DERIVA's
> legacy authentication / session-broker service and its session API -- the `client` /
> `attributes` document returned by `GET /session` that DERIVA components consume for
> identity and group/ACL decisions. It is **not** the W3C Web Authentication standard
> (WebAuthn / FIDO2, i.e. passkeys and security keys); the two are unrelated despite the
> shared name. (The W3C standard may separately appear upstream at the NIH Login / login.gov
> authenticator layer as an AAL2 MFA method -- that is a distinct concern from DERIVA's
> `webauthn` session service named here.)

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

    C -->|"A1: /login<br/>A2: /authorize + /token"| Z
    Z -.->|"A1: Set-Cookie session<br/>A2: code, then session token"| C
    Z ==>|"upstream /authorize, then /token"| R
    R -.->|"code, then id_token"| Z
```

- **Downstream plane** (`Client <-> Credenza`): Credenza is the session broker -- either a plain OIDC RP
  issuing a session cookie (legacy webauthn login, Sec. 3 A1) or an OAuth 2.1 Authorization
  Server issuing codes/tokens (Sec. 3 A2).
- **Upstream plane** (`Credenza <-> RAS`): Credenza is the OIDC Relying Party to RAS.

Credenza spans both planes. PKCE, authorization codes, `state`, and `nonce` exist
*independently* on each.

| Plane          | Credenza role                                     | Peer                                       | Auth-code                                                                    | PKCE                                                                                                                                                                          | nonce / state                                               |
|----------------|---------------------------------------------------|--------------------------------------------|------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------|
| **Downstream** | OIDC RP + session broker (A1) / OAuth 2.1 AS (A2) | Webauthn consumer (A1) / OAuth client (A2) | A1: session cookie (no code); A2: Credenza-issued single-use code, 5 min TTL | A2: client supplies `code_challenge` (S256), required for public clients. A1: no downstream client PKCE -- but the upstream RAS exchange uses PKCE in both (see Upstream row) | client `state` echoed back (A2)                             |
| **Upstream**   | OIDC Relying Party                                | RAS OP                                     | RAS-issued, exchanged once by Credenza                                       | Credenza generates `code_verifier` per login                                                                                                                                  | Credenza generates `nonce` + `state`, validates in ID token |

The bearer token Credenza ultimately returns to the client is an **opaque Credenza
session key**, never the RAS access/ID token. RAS tokens are held server-side in the
session record. This is the core brokering property: downstream resource servers
introspect Credenza, not RAS.

---

## 2. RAS realm configuration

The upstream relationship is declared as a realm in `oidc_idp_profiles.json`. The `nih-ras` profile:

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

## 3. Flow A -- Browser sign-in

Credenza supports two downstream browser sign-in variants over the **same** upstream RAS
OIDC login. They differ only at the entry point (Sec. 3.2) and at session delivery
(Sec. 3.4); the upstream RAS leg (Sec. 3.3) is identical, and both create the same
`SessionType.USER` session.

- **(A1) Legacy session-cookie login (`rest/login.py`).** Credenza acts purely as an OIDC
  Relying Party and session broker: `GET /login` -> RAS -> `/callback` sets a session
  cookie and redirects to the caller, which then reads `GET /session` in the legacy
  webauthn shape (`client` / `attributes`). **This is the path under active test and the
  primary rollout target** -- it lets NIH-RAS drop in as a webauthn-compatible replacement
  for Globus for DERIVA and other existing webauthn consumers, with no client-side change.
- **(A2) OAuth 2.1 Authorization Code + PKCE (`rest/authorize.py` + `rest/token.py`).** The
  downstream OAuth Authorization Server path for OAuth-native clients: `GET /authorize`
  (client supplies a PKCE challenge) -> RAS -> `/callback` mints a single-use authorization
  code -> the client redeems it at `POST /token` for an opaque session key.

### 3.1 Sequence

**(A1) Legacy session-cookie login (primary / under test):**

```mermaid
sequenceDiagram
    autonumber
    participant C as Browser (webauthn consumer, e.g. DERIVA)
    participant Z as Credenza (OIDC RP / session broker)
    participant R as RAS (NIH Login OP)

    C->>Z: GET /login?referrer=...
    Z->>Z: Generate state + upstream nonce + code_verifier (PKCE),<br/>store authn_request_ctx (no oauth_client_id)
    Z-->>C: 302 -> RAS authorization_endpoint (upstream PKCE)
    C->>R: GET RAS /authorize
    Note over R: User authenticates at NIH Login (AAL2 / IAL2)
    R-->>C: 302 -> Credenza /callback?code&state
    C->>Z: GET /callback?code&state
    Z->>R: POST RAS /token (code + Credenza code_verifier)
    R-->>Z: id_token, access_token (+ userinfo claims)
    Z->>Z: Validate id_token + nonce, enforce required_acr (AAL2+IAL2), userinfo fallback
    Z->>Z: Create USER session (SessionType.USER)
    Z-->>C: 302 -> referrer + Set-Cookie session key (HttpOnly, Secure, SameSite=Lax)
    C->>Z: GET /session (cookie)
    Z-->>C: legacy webauthn session (client / attributes)
```

**(A2) OAuth 2.1 Authorization Code + PKCE (OAuth-native clients):**

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

### 3.2 Step 1 -- Browser entry (two variants)

**(A1) `GET /login` -- legacy session-cookie login (the path under test).** Handled by
`rest/login.py`. There is no downstream client, `redirect_uri`, or client-side PKCE to
negotiate -- Credenza is itself the consumer's broker. The only input is an optional
`referrer`. If a valid session cookie already exists the request short-circuits to a
redirect. Otherwise, Credenza generates `state` (a UUID), an upstream `nonce`, and an
upstream `code_verifier`, stores a minimal `authn_request_ctx` with **no** `oauth_*` keys
(so `is_oauth_flow` is false at the callback), and 302-redirects to RAS.

**(A2) `GET /authorize` -- OAuth 2.1 AS (for OAuth-native clients).** Handled by
`rest/authorize.py`, with strict validation before any redirect:

- `client_id` -- must exist and be enabled in the client registry (else `400`/`401`, **no
  redirect**, because the `redirect_uri` is not yet trusted).
- `redirect_uri` -- must **exactly** match a registered `allowed_redirect_uris` entry.
- `response_type` -- must be `code`.
- `code_challenge` -- **PKCE** is required for public clients; `code_challenge_method`
  must be `S256` (the `plain` method is rejected for everyone).
- `scope` / `resource` -- must be within the client's `allowed_scopes` / `allowed_resources`.

Both variants then open the **upstream** leg to RAS via
`create_authorization_url(use_pkce=ENABLE_PKCE, state=..., nonce=...)`, generating Credenza's
own upstream `code_verifier` and `nonce`, and stash them in a transient `authn_request_ctx`
keyed by the upstream `state`. **PKCE on the RAS exchange is on by default (`ENABLE_PKCE`)
for both A1 and A2** -- the legacy `/login` path is not a weaker exchange; it simply has no
*downstream* client-PKCE leg because there is no downstream OAuth client. The A2 path additionally records the `oauth_*` keys that
later drive code issuance:

```text
authn_request_ctx[state] = {
  nonce, code_verifier, scope, realm, redirect_uri (=/callback),
  referrer,                                            # A1 (legacy login) only
  # --- A2 (OAuth AS) only: ---
  oauth_client_id, oauth_redirect_uri, oauth_state,
  oauth_scope, oauth_resources,
  oauth_code_challenge, oauth_code_challenge_method,   # the CLIENT's PKCE challenge
  oauth_session_ttl
}
```

The presence of `oauth_client_id` is exactly what the callback uses to tell the two paths
apart (`is_oauth_flow`). For A2 the client's PKCE challenge is carried here and verified at
`/token` time (not now).

### 3.3 Step 2 -- `GET /callback` (upstream RAS leg, shared by A1 and A2)

RAS redirects back with its authorization code to the single `/callback` in `rest/login.py`.
Both variants run identical upstream processing here and only branch on `is_oauth_flow` at
the very end (Sec. 3.4):

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
6. Creates a `SessionType.USER` session holding the RAS tokens + userinfo. For A2 the
   session is bound to the `oauth_resources` / `oauth_session_ttl` from the original
   `/authorize`; for A1 (`/login`) it follows the default interactive session policy.

### 3.4 Step 3 -- session delivery (where A1 and A2 diverge)

**(A1) Legacy cookie -- the path under test.** The callback sets a session **cookie** and
302-redirects to the `referrer`. There is no authorization code and no `/token` call: the
consumer is now authenticated and reads `GET /session` (cookie-authenticated) in the legacy
webauthn shape. Sec. 3.5 does **not** apply to A1.

What the cookie contains: **only the opaque Credenza session key** -- a random, unguessable
lookup token into the server-side session store. The RAS access/ID/refresh tokens and the
userinfo (including `federated_identities_ial2`) are **never** placed in the cookie; they
are held server-side in the session record (AES-GCM encrypted at rest) and are reachable
only by presenting the session key. The cookie is therefore a bearer credential for the
Credenza session, not a token container.

Cookie attributes (`rest/login.py`):

- `HttpOnly` -- not readable from JavaScript, mitigating session-key theft via XSS.
- `Secure` -- transmitted only over HTTPS.
- `SameSite=Lax` -- withheld on cross-site subrequests (CSRF mitigation) while still sent on
  top-level navigations, so the post-login redirect to the consumer works.
- `Domain` -- from `COOKIE_DOMAIN`: unset = host-only (exact FQDN); `true` = the registrable
  base domain (computed via the public suffix list) so one session can be shared across
  sibling service subdomains; or an explicit domain string.
- name from `COOKIE_NAME`; no `Max-Age`/`Expires`, so it is a **session cookie** (dropped
  when the browser closes) while the authoritative lifetime is the server-side session TTL.
  `GET /logout` clears it (empty value, past expiry, same `Secure`/`HttpOnly`/`SameSite`).

**(A2) Single-use authorization code.** Credenza instead mints its **own** downstream
authorization code (distinct from the RAS code):

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

### 3.5 Step 4 -- `POST /token` (`grant_type=authorization_code`, A2 only)

(Applies only to the OAuth-AS variant; the legacy login path already delivered the session
via cookie in Sec. 3.4.) `_handle_authorization_code_grant` (`rest/token.py`) performs, in order:

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

> _`GET /session` response for a `nih-ras` USER session -- legacy webauthn shape
> (`client` / `attributes`), as the A1 cookie path returns it under `ENABLE_LEGACY_API`._

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

The user opens `verification_uri`. 

The `verify_device` function:

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

The `device_callback` function then mirrors the browser callback: RAS code exchange (with PKCE),
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

The `RasSessionAugmentationProvider.build_identities()` function gocanonicalizes this **at render time**
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
| Session cookie hardening (A1)                                   | cookie holds only the opaque session key (no RAS tokens/claims); `HttpOnly`, `Secure`, `SameSite=Lax`; tokens held server-side (AES-GCM at rest)       | `rest/login.py`                                   |
| Token revocation peculiarity                                    | `skip_token_revocation` (RAS has no standard RFC 7009 endpoint)                                                                                        | `oidc_idp_profiles.json`                          |
| Refresh rotation + dead-grant eviction                          | rotated refresh token persisted each cycle; worker evicts on terminal OAuth error or after `MAX_REFRESH_FAILURES` (`session_evicted_refresh_failures`) | `refresh/refresh_worker.py`, `api/common/util.py` |

---

## 8. Endpoint reference

| Endpoint                                  | Method  | Plane      | Purpose                                                                     |
|-------------------------------------------|---------|------------|-----------------------------------------------------------------------------|
| `/.well-known/oauth-authorization-server` | GET     | Downstream | RFC 8414 AS metadata                                                        |
| `/login`                                  | GET     | Downstream | Legacy session-cookie login (A1, webauthn consumers -- the path under test) |
| `/authorize`                              | GET     | Downstream | OAuth 2.1 Authorization Code + PKCE (A2)                                    |
| `/callback`                               | GET     | Upstream   | RAS OIDC redirect handler (browser)                                         |
| `/token`                                  | POST    | Downstream | `authorization_code`, `device_code`, `token-exchange`, `client_credentials` |
| `/device_authorization` (`/device/start`) | POST    | Downstream | RFC 8628 device authorization request                                       |
| `/device/verify/{user_code}`              | GET     | Upstream   | User verification -> RAS login                                              |
| `/device/callback`                        | GET     | Upstream   | RAS OIDC redirect handler (device)                                          |
| `/session`                                | GET/PUT | Downstream | Session introspection / extension                                           |
| `/introspect`                             | POST    | Downstream | RFC 7662 token introspection (resource servers)                             |
| `/logout`                                 | GET     | Downstream | Session termination                                                         |

