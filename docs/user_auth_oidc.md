# User Auth (OIDC) in Credenza

## 1. Overview

Credenza provides **human user authentication** by acting as an **OIDC Relying Party (RP)** in front of one or more OIDC
Identity Providers (IdPs) / Operating Parties (OPs).

It implements:

- **Browser login/logout** (Authorization Code flow + PKCE when enabled).
- **Device Code / headless login** for CLI or constrained devices.
- A **server-side session store** that holds user claims (`userinfo`) and tokens (access/refresh/id token, plus optional additional tokens).
- **Session introspection and renewal** via the `/authn/session` endpoint.
- Optional **session augmentation** providers (e.g., Globus) to enrich groups/claims or manage additional downstream tokens.

User sessions are stored as `SESSION_TYPE.user` in the session store and are authenticated via:

- Cookie (browser) **or**
- `Authorization: Bearer <session_key>` (API / headless)

> Note: Credenza also supports **service/M2M tokens**. This document focuses on the **user flow**, but points out where
> service-session logic intersects `/authn/session` behavior.

---

## 2. Identity Provider configuration: `OIDC_IDP_PROFILES`

Credenza uses an `oidc_idp_profiles.json` (loaded into `app.config["OIDC_IDP_PROFILES"]`) to define one or more IdP
profiles. Each top-level key (e.g., `"keycloak"`, `"globus"`) is a **realm/profile name** used by Credenza.

### 2.1 Example `oidc_idp_profiles.json`:

```json
{
  "keycloak": {
    "discovery_url": "http://keycloak:8080/auth/realms/deriva/.well-known/openid-configuration",
    "scopes": "openid email profile",
    "client_secret_file": "secrets/keycloak_client_secret.json"
  },
  "okta": {
    "discovery_url": "https://trial-1234567.okta.com/.well-known/openid-configuration",
    "scopes": "openid email profile groups",
    "client_secret_file": "secrets/okta_client_secret.json"
  },
  "cognito": {
    "discovery_url": "https://cognito-idp.us-west-2.amazonaws.com/us-west-2_123456789/.well-known/openid-configuration",
    "scopes": "openid email profile",
    "request_offline_access_scope_in_device_flow": false,
    "logout_url_params": {
       "client_id": "${COGNITO_CLIENT_ID}",
       "logout_uri": "https://localhost"
    },
    "client_secret_file": "secrets/cognito_client_secret.json"
  },
  "globus": {
    "discovery_url": "https://auth.globus.org/.well-known/openid-configuration",
    "introspect_url": "https://auth.globus.org/v2/oauth2/token/introspect",
    "logout_url": "https://auth.globus.org/v2/web/logout",
    "logout_url_params": {
      "redirect_uri": "https://localhost",
      "redirect_name": "homepage."
    },
    "scopes": "openid email profile urn:globus:auth:scope:groups.api.globus.org:view_my_groups_and_memberships https://auth.globus.org/scopes/identifiers.fair-research.org/writer",
    "accepted_scopes": [
      {
        "scope": "https://auth.globus.org/scopes/3ba21deb-66d8-482d-8a79-9c8ce54f6097/deriva_all",
        "issuer": "https://auth.globus.org"
      }
    ],
    "discovery_scopes": {
      "deriva-all": "https://auth.globus.org/scopes/3ba21deb-66d8-482d-8a79-9c8ce54f6097/deriva_all"
    },
    "session_augmentation_provider": "credenza.api.session.augmentation.globus_provider:GlobusSessionAugmentationProvider",
    "client_secret_file": "secrets/globus_client_secret.json"
  }
}
```

### 2.2 Common profile fields

#### `discovery_url` (required)
OIDC discovery endpoint used to bootstrap issuer metadata (authorization endpoint, token endpoint, JWKS, etc.).

#### `scopes` (recommended)
Space-delimited scopes requested during login/device auth. Typical values:
- `openid email profile`
- plus provider-specific scopes (e.g., `groups`, Globus groups scopes)

#### `client_secret_file` (required for confidential clients)
Path to a JSON file containing client credentials.

Example:
```json
{
  "client_id": "${CLIENT_ID}",
  "client_secret": "${CLIENT_SECRET}",
  "native_client_id": "${NATIVE_CLIENT_ID}"
}
```

### 2.3 Optional / provider-specific fields

#### `logout_url` and `logout_url_params`
Used to construct the upstream IdP logout URL during `/logout` (or legacy-mode redirects).

- `logout_url` overrides what might be discoverable.
- `logout_url_params` are appended as query params.

Examples:
- Cognito uses `client_id` + `logout_uri`.
- Globus uses `redirect_uri` + `redirect_name`.

#### `request_offline_access_scope_in_device_flow` (device flow)
Controls whether the device flow attempts to request offline access (refresh tokens) by including offline-access behavior
in the authorization URL generation.

- If `false`: device flow *won’t* try to request offline access scope behavior.
- If `true` or omitted: device flow will request offline access behavior if the client supports it.

#### `introspect_url` (Globus)
Some providers support token introspection. This can be used by augmentation providers or legacy compatibility helpers.

#### `accepted_scopes` / `discovery_scopes` (Globus)
Used to model Globus’ “scope aliasing” and acceptance of specific scopes minted by a particular issuer.

#### `session_augmentation_provider`
A dotted-path import string used to instantiate a provider that can:
- extract/manage **additional tokens** (downstream tokens) from login responses, and/or
- enrich user claims/groups using external calls.

---

## 3. Session model and token storage

Credenza stores user sessions in the session store with (typical fields):

- `session_type`: `SESSION_TYPE.user`
- `access_token`, `refresh_token`, `id_token`
- `scopes`: the granted scopes (space-delimited string)
- `userinfo`: normalized identity claims; includes at least `sub`, and often `email`, `name`, `groups`, etc.
- `additional_tokens`: a dict keyed by scope (or logical token name) with token material for downstream APIs.
- `session_metadata.{system|user}`: system-controlled metadata (e.g., token expiry timestamps, refresh expiry, device
session flags), or unconstrained user-space metadata that can be stored and associated with an authenticated session.

### 3.1 Effective scopes
Credenza exposes **effective scopes** as:

- the session’s primary `scopes` tokens **plus**
- any keys present in `session.additional_tokens`

This is used for auditing and responses (`get_effective_scopes(session)`).

---

## 4. Device flow (headless login)

The device flow supports a classic “device initiates, user completes in browser, device polls” pattern.

### 4.1 Endpoints

#### Start: `POST /authn/device/start`
Creates a new device flow and returns:

- `device_code`
- `user_code` (short code user types/uses)
- `verification_uri` (URL user visits)
- `interval` (poll interval)
- `expires_in` (DEVICE_TTL, currently 600s)

Supports query parameter:
- `?refresh=true|false` — stored in the flow and used later to decide whether background refresh is allowed.

#### Verify: `GET /authn/device/verify/<user_code>`
- Exchanges the `user_code` for a `device_code`.
- Generates a nonce + PKCE verifier (when enabled).
- Redirects the user agent to the IdP authorization URL.

Key implementation notes:
- `state` is set to the `device_code` (so callback can identify the flow).
- `redirect_uri` is `BASE_URL + /device/callback` and stored in the flow.
- The profile flag `request_offline_access_scope_in_device_flow` influences whether offline access is requested.

#### Callback: `GET /authn/device/callback`
Handles the IdP redirect back to Credenza.

Flow:
1. Validate `code` and `state`.
2. Load stored device-flow context using `state` as `device_code`.
3. Exchange `code` for tokens using the configured OIDC _native_ client (native_client=True).
4. Validate the ID token against the stored `nonce`.
5. Compute `refresh_expires_at`:
   - If provider returns `refresh_expires_in` and it’s non-zero, use it.
   - Else fall back to `MAX_REFRESH_TOKEN_LIFETIME` (default 14 days) * 86400 seconds.
6. Create a user session in the store (expires_at = refresh_expires_at).
7. If augmentation is configured and **deferred augmentation** is enabled, do a second augmentation pass and update the session.
8. Mark the device flow as verified, stash `session_key`, and clear nonce/verifier.

Response:
- Returns a simple success string to the user agent: `"Device authorization complete. You may return to the device."`

#### Poll: `POST /authn/device/token`
The device polls this endpoint with JSON body:
```json
{"device_code": "..."}
```

Behavior:
- Enforces polling interval; too-fast polling returns `429 slow_down`.
- If not verified yet, returns `{"error": "authorization_pending"}` with HTTP 403.
- When verified:
  - Looks up the created session by stored `session_key`.
  - Deletes the device flow.
  - Returns:
    - `access_token`: the **session_key** (opaque bearer)
    - `token_type`: `"Bearer"`
    - `expires_in`: remaining seconds in the session

#### Device logout: `POST /authn/device/logout`
- Uses `get_current_session()` to resolve session from bearer or cookie.
- Confirms `session_metadata.system["device_session"]` is true.
- Revokes upstream tokens (if user session; service sessions are skipped in `revoke_tokens`).
- Deletes the session from the store.
- Returns `{"status": "logged out"}`.

### 4.2 Device-session metadata

During `/authn/device/callback`, Credenza sets system metadata including:

- `device_session`: true
- `allow_automatic_refresh`: from `/device/start?refresh=true`
- `offline_access_granted`: whether a refresh token was issued
- `refresh_expires_at`: computed (see above)
- `token_expires_at`: from token response if present

---

## 5. Session introspection and renewal

### 5.1 `/authn/whoami` (GET)
Returns a JSON object including:
- `remote_addr`, `xff`, `proto`
- merged with `session.userinfo`

### 5.2 `/authn/session` (GET, PUT)
This is the main “introspection” endpoint.

#### GET `/authn/session`
- Resolves current session via `get_current_session()`.
- Returns a structured session JSON response (new API or legacy format depending on `ENABLE_LEGACY_API`).

#### PUT `/authn/session`
Used as a “keepalive / refresh” endpoint.

Common behavior:
- Loads current session.
- Applies different renewal logic depending on session type (user vs service).
- Updates the session in the store and emits `audit_event("session_updated", ...)`.
- Returns the same response shape as GET.

### 5.3 Service-session audience enforcement (important intersection)

When the session is **service** (`SESSION_TYPE.service`), `/authn/session` enforces audience binding at introspection time:

- Callers must pass at least one `resource` hint via repeated params:
  - `?resource=A&resource=B`
- The session must have a non-empty `userinfo.aud` claim (normalized into a string set).
- Access is allowed only if `set(resources) ∩ set(token_audiences)` is non-empty.

Fail-fast cases (403):
- Empty `aud` in the stored session (`service_session_audience_misconfig`).
- Missing `resource` param (`service_session_audience_denied`, reason `missing_resource_param`).
- No intersection (`service_session_audience_denied`, reason `no_intersection`).

On success:
- Emits `service_session_audience_ok` and continues.

> User sessions **skip** all audience checks here because the OIDC login flow already validated the token issuance context.

### 5.4 User-session refresh rules on PUT

For **user** sessions, PUT `/authn/session` may:
- enforce refresh-token lifetime (`refresh_expires_at`) and hard-expire sessions near expiry,
- refresh the upstream access token (if `refresh_upstream=true` or legacy mode forces it),
- refresh any additional tokens with refresh tokens,
- re-enrich userinfo via the session augmentation provider.

Key toggles:
- `ENABLE_LEGACY_API`: forces upstream refresh behavior and changes response shape.
- `refresh_upstream` query param: controls upstream refresh attempt (best-effort).

### 5.5 `/authn/session` PATCH
Allows patching session metadata tags (user-scope tags) via JSON dict.

### 5.6 `/authn/session` DELETE
- If `ENABLE_LEGACY_API` is true, redirects to `/logout`.
- Otherwise revokes upstream tokens (user sessions) and deletes session from store.
- Clears cookie.

---

## 6. How realms/profiles are selected (`get_realm`)

Credenza resolves a realm/profile name via:

- explicit realm parameter (if valid and present in `OIDC_IDP_PROFILES`), otherwise
- configuration variable `DEFAULT_REALM` (must be configured, else abort 400)

Device flow currently uses `DEFAULT_REALM` when starting a flow.

---

## 7. Practical examples

### 7.1 Start a device flow
```bash
curl -sS -X POST "https://<credenza>/authn/device/start?refresh=true" | jq
```

### 7.2 User completes verification in browser
Open the returned `verification_uri` and complete login.

### 7.3 Device polls for token
```bash
curl -sS -X POST "https://<credenza>/authn/device/token"   -H "Content-Type: application/json"   -d '{"device_code":"<device_code>"}' | jq
```

### 7.4 Introspect session
```bash
curl -sS -H "Authorization: Bearer <access_token>"   "https://<credenza>/authn/session" | jq
```

### 7.5 Refresh/keepalive user session
```bash
curl -sS -X PUT -H "Authorization: Bearer <access_token>"   "https://<credenza>/authn/session?refresh_upstream=true" | jq
```

---

## 8. Operational notes

- Prefer enabling **PKCE** (`ENABLE_PKCE`) for browser and device flows.
- Ensure `BASE_URL` is correct and matches the redirect URIs registered with each IdP.
- For production, ensure reverse-proxy headers are handled correctly (ProxyFix or mod_remoteip) so `request.remote_addr`
  is meaningful for audit/rate limiting.
- If you use augmentation providers (e.g., Globus), document and monitor their external calls and token refresh behavior,
  since they can affect performance and session update frequency.

