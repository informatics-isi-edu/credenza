# Credenza Configuration Guide

Credenza is configured through three complementary mechanisms:

1. **`credenza.env`** -- environment variables controlling runtime behavior
2. **`oidc_idp_profiles.json`** -- upstream identity provider definitions (one per realm)
3. **`client_registry.json`** -- registered OAuth clients and their authorization policy

All three are loaded at startup. Configuration errors fail fast.

---

## 1. `credenza.env`

Environment variables are loaded from one of the following locations (first match wins):

```
/etc/credenza/credenza.env
~/credenza.env
./config/credenza.env
./credenza.env
```

All Credenza variables are prefixed with `CREDENZA_`. The prefix is stripped when the variable is
mapped to the internal config key (e.g., `CREDENZA_BASE_URL` -> `BASE_URL`). Variables already
present in `os.environ` override `.env` file values.

Boolean values are parsed from strings: `"true"` / `"1"` / `"yes"` -> `True`.
JSON-structured values (lists, dicts) are accepted as JSON strings.

### 1.1 Core

| Variable                 | Default                    | Description                                                                                                                  |
|--------------------------|----------------------------|------------------------------------------------------------------------------------------------------------------------------|
| `CREDENZA_BASE_URL`      | `https://<hostname>/authn` | Public base URL of the service. Used to construct callback, verification, and redirect URIs. Must not have a trailing slash. |
| `CREDENZA_DEFAULT_REALM` | `default`                  | OIDC realm used when no realm is specified on a request. Must match a key in `oidc_idp_profiles.json`.                       |
| `CREDENZA_COOKIE_NAME`   | `credenza`                 | Name of the browser session cookie. Set to `webauthn` automatically when `ENABLE_LEGACY_API=true`.                           |
| `CREDENZA_COOKIE_DOMAIN` | *(unset)*                  | Domain attribute for the session cookie. Unset means same-origin only.                                                       |

### 1.2 Session and storage

| Variable                            | Default   | Description                                                                                                                                        |
|-------------------------------------|-----------|----------------------------------------------------------------------------------------------------------------------------------------------------|
| `CREDENZA_STORAGE_BACKEND`          | `memory`  | Storage backend: `memory`, `redis`, `valkey`, `postgresql`, `sqlite`. `memory` is single-process only and not suitable for production.             |
| `CREDENZA_STORAGE_BACKEND_URL`      | *(unset)* | Connection URL for the storage backend (e.g., `redis://localhost:6379/0`, `postgresql://user:pass@host/db`). Required for all non-memory backends. |
| `CREDENZA_STORAGE_BACKEND_KWARGS`   | *(unset)* | JSON object of additional keyword arguments passed to the storage backend constructor.                                                             |
| `CREDENZA_SESSION_TTL`              | `2100`    | Default session TTL in seconds (35 minutes). Applied when no client-specific TTL is set.                                                           |
| `CREDENZA_SESSION_EXPIRY_THRESHOLD` | `300`     | Seconds before session expiry at which `PUT /session` triggers a token refresh.                                                                    |
| `CREDENZA_TOKEN_EXPIRY_THRESHOLD`   | `300`     | Seconds before access token expiry at which upstream refresh is attempted.                                                                         |
| `CREDENZA_ENCRYPT_SESSION_DATA`     | `false`   | Encrypt session data at rest using AES-GCM. Requires `CREDENZA_ENCRYPTION_KEY`.                                                                    |
| `CREDENZA_ENCRYPTION_KEY`           | *(unset)* | Encryption key for AES-GCM session encryption. Required if `ENCRYPT_SESSION_DATA=true`.                                                            |

### 1.3 Authentication and flows

| Variable                              | Default               | Description                                                                                               |
|---------------------------------------|-----------------------|-----------------------------------------------------------------------------------------------------------|
| `CREDENZA_ENABLE_PKCE`                | `true`                | Require PKCE (`S256`) on all OIDC authorization requests. Disable only for IDPs that do not support PKCE. |
| `CREDENZA_POST_LOGIN_REDIRECT`        | `/`                   | Redirect destination after successful browser login when no `referrer` is present.                        |
| `CREDENZA_POST_LOGOUT_REDIRECT_URL`   | `https://<hostname>/` | Redirect destination after browser logout.                                                                |
| `CREDENZA_MAX_REFRESH_TOKEN_LIFETIME` | `14`                  | Maximum device session lifetime in days when the IDP does not provide `refresh_expires_in`.               |

### 1.4 Device Authorization Grant

| Variable                        | Default | Description                                                                                                           |
|---------------------------------|---------|-----------------------------------------------------------------------------------------------------------------------|
| `CREDENZA_DEVICE_FLOW_TTL`      | `600`   | Device authorization flow expiry in seconds (10 minutes). Applies to both the device code and the user code.          |
| `CREDENZA_DEVICE_POLL_INTERVAL` | `3`     | Minimum polling interval in seconds returned to device clients. Clients that poll faster receive a `slow_down` error. |

### 1.5 Client registry

| Variable                              | Default | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
|---------------------------------------|---------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `CREDENZA_ALLOW_UNREGISTERED_CLIENTS` | `false` | Allow clients not present in the registry. When enabled, unregistered clients bypass grant type, scope, and resource policy checks. Not recommended for production.                                                                                                                                                                                                                                                                                                                                                                   |
| `CREDENZA_LOOPBACK_REDIRECT_ANY_PORT` | `true`  | Apply the RFC 8252 sec. 7.3 loopback exception when matching `redirect_uri` at `/authorize`. When enabled, an `http` loopback redirect (`localhost`, `127.0.0.1`, `[::1]`) matches a registered loopback URI with the same scheme, host, and path regardless of port, so native apps using an ephemeral callback port do not need every port pre-registered. Only the port is relaxed; scheme, host token, and path must still match a registered loopback entry. Set `false` for strict exact-match (RFC 6749) on all redirect URIs. |

### 1.6 Rate limiting

| Variable                        | Default | Description                                                                                                                                                                           |
|---------------------------------|---------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `CREDENZA_ENABLE_RATE_LIMITING` | `true`  | Enable IP-based rate limiting on public-facing endpoints. Per-client rate limiting on token, introspect, revoke, and exchange endpoints is always active when a client is registered. |

### 1.7 Reverse proxy

| Variable                   | Default | Description                                                                                                                                                                                     |
|----------------------------|---------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `CREDENZA_ENABLE_PROXYFIX` | `false` | Enable Werkzeug `ProxyFix` to derive real client IP from `X-Forwarded-For`. Required when Credenza runs behind a reverse proxy and rate limiting or audit logging must reflect real client IPs. |
| `CREDENZA_PROXYFIX_DEPTH`  | `1`     | Number of trusted proxy hops. Set to `2` for cloud LB -> reverse proxy -> Credenza topologies.                                                                                                  |

### 1.8 Background worker

| Variable                                | Default | Description                                                                                                                          |
|-----------------------------------------|---------|--------------------------------------------------------------------------------------------------------------------------------------|
| `CREDENZA_ENABLE_REFRESH_WORKER`        | `true`  | Enable the background device session refresh thread. Refreshes upstream access tokens for active device sessions before they expire. |
| `CREDENZA_REFRESH_WORKER_POLL_INTERVAL` | `60`    | Background refresh worker polling interval in seconds.                                                                               |

### 1.9 Observability

| Variable                       | Default              | Description                                                               |
|--------------------------------|----------------------|---------------------------------------------------------------------------|
| `CREDENZA_ENABLE_HEALTH_CHECK` | `true`               | Enable the `GET /health` endpoint.                                        |
| `CREDENZA_AUDIT_LOGFILE_PATH`  | `credenza-audit.log` | Path to the structured JSON audit log file.                               |
| `CREDENZA_AUDIT_USE_SYSLOG`    | `false`              | Send audit events to syslog instead of (or in addition to) the log file.  |
| `CREDENZA_DEBUG`               | `false`              | Enable DEBUG-level logging. Takes precedence over the Flask `DEBUG` flag. |
| `CREDENZA_DEBUG_PERF`          | `false`              | Log per-request performance timing at DEBUG level.                        |

### 1.10 Config file paths

| Variable                          | Default                                | Description                              |
|-----------------------------------|----------------------------------------|------------------------------------------|
| `CREDENZA_OIDC_IDP_PROFILES_FILE` | `config/oidc_idp_profiles.json`        | Path to the IDP profiles config file.    |
| `CREDENZA_CLIENT_REGISTRY_FILE`   | `config/client_registry.json`          | Path to the client registry config file. |
| `CREDENZA_TRUSTED_ISSUERS_FILE`   | `config/oidc_idp_trusted_issuers.json` | Path to the trusted OIDC issuers list.   |

### 1.11 Legacy compatibility

| Variable                           | Default                       | Description                                                                                                             |
|------------------------------------|-------------------------------|-------------------------------------------------------------------------------------------------------------------------|
| `CREDENZA_ENABLE_LEGACY_API`       | `false`                       | Enable the legacy (pre-OAuth-AS) API surface. Enables the `GET /discovery` endpoint and legacy session lookup behavior. |
| `CREDENZA_LEGACY_DEFAULT_RESOURCE` | `urn:deriva:rest:service:all` | Default resource identifier injected in legacy mode when no resource is specified on a request.                         |

---

## 2. `oidc_idp_profiles.json`

Defines one or more upstream OpenID Connect Identity Providers. Each top-level key is the
**realm name** used throughout the system (in `DEFAULT_REALM`, client records, session data, etc.).

```json
{
  "<realm-name>": {
    ...
  },
  "<realm-name>": {
    ...
  }
}
```

### 2.1 Required fields

| Field                | Description                                                                                  |
|----------------------|----------------------------------------------------------------------------------------------|
| `client_secret_file` | Path to a JSON file containing the OIDC client credentials for this realm. See format below. |

Either `discovery_url` or all of the explicit endpoint fields must be provided.

| Field           | Description                                                                                                                                                                     |
|-----------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `discovery_url` | URL to the OIDC provider's discovery document (`.well-known/openid-configuration`). Endpoints are derived from the discovery document and may be individually overridden below. |

### 2.2 Endpoint overrides

These override the corresponding value from the discovery document. Useful when the discovery
document is incorrect or when an endpoint is at a non-standard URL.

| Field            | Description                                            |
|------------------|--------------------------------------------------------|
| `authorize_url`  | Authorization endpoint URL.                            |
| `token_url`      | Token endpoint URL.                                    |
| `revocation_url` | Token revocation endpoint URL.                         |
| `userinfo_url`   | UserInfo endpoint URL.                                 |
| `introspect_url` | Token introspection endpoint URL.                      |
| `logout_url`     | End-session (logout) endpoint URL.                     |
| `jwks_uri`       | JWKS endpoint URL for ID token signature verification. |
| `issuer`         | Expected issuer (`iss`) value for ID token validation. |

### 2.3 Optional fields

| Field                                         | Default                              | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
|-----------------------------------------------|--------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `scopes`                                      | `openid email profile`               | Space-separated scopes requested on the authorization URL. This is the IDP-plane scope — what Credenza asks the upstream IDP for. It is independent of what downstream OAuth clients request via `/authorize`. The IDP profile `scopes` must cover all identity claims that any registered client may request.                                                                                                                                                                                                       |
| `issuable_scopes`                             | *(derived from `scopes`)*            | List of OIDC scope strings Credenza can actually deliver to downstream OAuth clients given this IDP's configuration. Used as `scopes_supported` in the RFC 8414 discovery document and to validate client registry entries at startup. Required when `scopes` contains IDP-internal scope strings (e.g., Globus URN scopes) that should not be advertised to clients. When absent, `scopes_supported` is derived from `scopes` directly.                                                                             |
| `scope_expected_claims`                       | *(unset)*                            | Dict mapping scope names to lists of claim names expected in the ID token when that scope is requested. Shallow-merged over the built-in defaults (`email` → `["email"]`, `profile` → `["name", "preferred_username"]`); only the scopes declared here are affected, all others retain their defaults. Use this to add custom IDP scopes (e.g., `"groups": ["group_membership"]`) or to adjust the expected claims for a standard scope (e.g., Globus `profile` → `["name", "preferred_username", "identity_set"]`). |
| `skip_userinfo_fallback`                      | `false`                              | When `true`, suppresses the automatic userinfo endpoint call that fires when key identity claims are missing from the ID token. Set this for IDPs whose userinfo endpoint is unavailable, rate-limited, or known to add no value.                                                                                                                                                                                                                                                                                    |
| `redirect_uri`                                | *(unset)*                            | Override for the OIDC redirect URI. Normally derived from `BASE_URL`.                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `logout_url_params`                           | *(unset)*                            | Dict of extra query parameters appended to the logout redirect URL.                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `request_offline_access_scope_in_device_flow` | `true`                               | Whether to include `offline_access` in the scope when initiating a device flow authorization. Set to `false` for IDPs that do not support `offline_access` (e.g., Cognito).                                                                                                                                                                                                                                                                                                                                          |
| `accepted_scopes`                             | *(unset)*                            | List of `{"scope": "...", "issuer": "..."}` objects representing additional scopes the IDP may issue that Credenza should accept. Used by some augmentation providers (e.g., Globus).                                                                                                                                                                                                                                                                                                                                |
| `discovery_scopes`                            | *(unset)*                            | Dict of `name -> scope-url` for IDP-specific named scopes. Used by augmentation providers.                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `session_augmentation_provider`               | `DefaultSessionAugmentationProvider` | Dotted Python import path to a custom `SessionAugmentationProvider` class for this realm (e.g., `credenza.api.session.augmentation.globus_provider:GlobusSessionAugmentationProvider`).                                                                                                                                                                                                                                                                                                                              |

> **IDP scope vs. OAuth client scope:** `scopes` is what Credenza requests from the upstream IDP when it acts as a Relying Party. It speaks the IDP's vocabulary (standard OIDC scopes for Keycloak/Okta/Cognito; URN scopes for Globus). Downstream clients interact with Credenza's OAuth AS surface via `/authorize` and declare their own scope requests there — those are validated against `client_registry.json`, not forwarded to the IDP. `issuable_scopes` bridges the two planes by declaring what Credenza can actually deliver to clients.

### 2.4 `client_secret_file` format

The file referenced by `client_secret_file` must be a JSON object:

```json
{
  "client_id": "my-oidc-client-id",
  "client_secret": "my-oidc-client-secret",
  "native_client_id": "my-public-oidc-client-id"
}
```

| Field              | Description                                                                                                                                  |
|--------------------|----------------------------------------------------------------------------------------------------------------------------------------------|
| `client_id`        | OIDC client ID registered with the IDP. Used for the browser-facing authorization code flow.                                                 |
| `client_secret`    | OIDC client secret. Set to `null` or omit for public clients.                                                                                |
| `native_client_id` | Optional. If present, used as the client ID for device flow (native/public client) authorization requests to the IDP instead of `client_id`. |

### 2.5 Example

```json
{
  "keycloak": {
    "discovery_url": "https://keycloak.example.org/realms/my-realm/.well-known/openid-configuration",
    "scopes": "openid email profile",
    "client_secret_file": "secrets/keycloak_client_secret.json"
  },
  "cognito": {
    "discovery_url": "https://cognito-idp.us-west-2.amazonaws.com/us-west-2_XXXXXXX/.well-known/openid-configuration",
    "scopes": "openid email profile",
    "request_offline_access_scope_in_device_flow": false,
    "logout_url_params": {
      "client_id": "my-cognito-client-id",
      "logout_uri": "https://myapp.example.org/"
    },
    "client_secret_file": "secrets/cognito_client_secret.json"
  },
  "globus": {
    "discovery_url": "https://auth.globus.org/.well-known/openid-configuration",
    "scopes": "openid email profile urn:globus:auth:scope:groups.api.globus.org:view_my_groups_and_memberships",
    "issuable_scopes": ["openid", "email", "profile"],
    "scope_expected_claims": {
      "profile": ["name", "preferred_username", "identity_set"]
    },
    "session_augmentation_provider": "credenza.api.session.augmentation.globus_provider:GlobusSessionAugmentationProvider",
    "client_secret_file": "secrets/globus_client_secret.json"
  }
}
```

In the Globus example: `scopes` includes a Globus URN scope that is IDP-internal and should not be advertised to clients. `issuable_scopes` restricts the RFC 8414 discovery document to the three standard OIDC scopes that clients can actually request. `scope_expected_claims` extends the `profile` scope check to include `identity_set`, a Globus-specific claim, so the userinfo fallback fires when it is absent.

---

## 3. `client_registry.json`

Defines registered OAuth clients and their authorization policy. The registry is loaded at startup;
changes require a restart. The JSON key for each client entry is used as the authoritative
`client_id`.

```json
{
  "version": "1",
  "clients": {
    "<client-id>": {
      ...
    },
    "<client-id>": {
      ...
    }
  }
}
```

The top-level `version` string is informational and used for audit/drift detection.

### 3.1 Common client fields

| Field                               | Default     | Description                                                                                                                                                                                                                                                                            |
|-------------------------------------|-------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `desc`                              | *(unset)*   | Human-readable description of this client. Informational only.                                                                                                                                                                                                                         |
| `enabled`                           | `true`      | If `false`, all requests from this client are rejected with `401 unauthorized_client`.                                                                                                                                                                                                 |
| `public`                            | `false`     | If `true`, the client is a public client (no adapter authentication required). PKCE is required for `authorization_code` grant.                                                                                                                                                        |
| `realm`                             | *(derived)* | OIDC realm this client is associated with. Defaults to a deterministic URN derived from the `client_id`. Set explicitly to a realm name from `oidc_idp_profiles.json` when claim mapping or augmentation is needed.                                                                    |
| `allowed_grant_types`               | `[]`        | Grant types this client may use. Supported values: `authorization_code`, `client_credentials`, `token_exchange` (`urn:ietf:params:oauth:grant-type:token-exchange`), `device_code` (`urn:ietf:params:oauth:grant-type:device_code`). Short aliases are resolved to canonical URN form. |
| `allowed_resources`                 | `[]`        | Resource identifiers (URIs or URNs) this client may request tokens for. Enforced on all grant types.                                                                                                                                                                                   |
| `default_resources`                 | `[]`        | Resources bound to issued tokens when the client does not request a specific resource. Must be a subset of `allowed_resources`.                                                                                                                                                        |
| `allowed_scopes`                    | `[]`        | Scopes this client may request.                                                                                                                                                                                                                                                        |
| `default_scopes`                    | `[]`        | Scopes included in issued tokens when the client does not request specific scopes. Must be a subset of `allowed_scopes`.                                                                                                                                                               |
| `allowed_auth_methods`              | `[]`        | Authentication methods accepted for this client: `client_secret_basic`, `client_secret_post`, `aws_presigned_getcalleridentity`.                                                                                                                                                       |
| `allowed_redirect_uris`             | `[]`        | Exact-match list of redirect URIs permitted for `authorization_code` grant. Required for any client using `authorization_code`.                                                                                                                                                        |
| `allowed_introspection_resources`   | `[]`        | If non-empty, this client may only introspect tokens that carry at least one of these resource identifiers. Empty means no restriction. Use this to prevent resource servers from inspecting tokens outside their audience.                                                            |
| `allowed_token_exchange_targets`    | `[]`        | Resources this client may request via token exchange (RFC 8693). Default-deny: empty means token exchange is not permitted even if the grant type is allowed.                                                                                                                          |
| `additional_claims`                 | `{}`        | Static claims merged into the token introspection response for sessions issued to this client.                                                                                                                                                                                         |
| `allowed_claims`                    | `[]`        | Subset of `additional_claims` keys that may be included in responses.                                                                                                                                                                                                                  |
| `max_session_ttl_seconds`           | `1800`      | Maximum TTL for a single session issuance. Requested TTLs are clamped to this value.                                                                                                                                                                                                   |
| `absolute_session_lifetime_seconds` | `86400`     | Hard upper bound on total session lifetime. A session cannot be extended past `created_at + absolute_session_lifetime_seconds`.                                                                                                                                                        |

### 3.2 Adapter block

The `adapter` block is required for confidential clients. It identifies the authentication mechanism
and provides its configuration. Omit for public clients (`"public": true`).

```json
"adapter": {
"name": "<adapter-name>",
...adapter-specific fields...
}
```

#### client_secret adapter

Authenticates clients using a shared secret via `client_secret_basic` (HTTP Basic) or
`client_secret_post` (form body).

| Field                       | Description                                                                                                 |
|-----------------------------|-------------------------------------------------------------------------------------------------------------|
| `name`                      | `"client_secret"`                                                                                           |
| `client_secret`             | Plaintext secret. Accepted if provided; prefer `client_secret_hash` for stored credentials.                 |
| `client_secret_hash`        | Pre-hashed secret in the form `bcrypt:<hash>`. Takes precedence over `client_secret` when both are present. |
| `client_secret_hash_scheme` | Hash scheme identifier. Currently `bcrypt` is the supported value.                                          |

#### aws_presigned adapter

Authenticates AWS workloads using a presigned STS `GetCallerIdentity` URL. No shared secret is
required; identity is proved cryptographically via AWS SigV4.

| Field                     | Description                                                             |
|---------------------------|-------------------------------------------------------------------------|
| `name`                    | `"aws_presigned"`                                                       |
| `role_arn`                | The IAM role ARN that the authenticating workload must be assuming.     |
| `request_attempts`        | *(optional)* Number of STS call attempts before failing. Default: `3`.  |
| `request_backoff_seconds` | *(optional)* Backoff between retry attempts in seconds. Default: `0.5`. |

#### Custom adapters

Additional adapter types can be registered at startup via the `@register_adapter` decorator.
See the `AdapterInterface` base class in `credenza/api/auth/client/adapters/adapter.py`.

### 3.3 Example

```json
{
  "version": "1",
  "clients": {
    "my-cli-tool": {
      "desc": "Public device flow client for the CLI",
      "public": true,
      "allowed_grant_types": [
        "device_code"
      ],
      "allowed_resources": [
        "https://api.example.org/"
      ],
      "max_session_ttl_seconds": 7200
    },
    "my-web-app": {
      "desc": "Confidential web application",
      "adapter": {
        "name": "client_secret",
        "client_secret_hash": "bcrypt:$2b$12$..."
      },
      "allowed_grant_types": [
        "authorization_code",
        "token_exchange"
      ],
      "allowed_auth_methods": [
        "client_secret_basic"
      ],
      "allowed_redirect_uris": [
        "https://app.example.org/callback"
      ],
      "allowed_resources": [
        "https://api.example.org/"
      ],
      "allowed_scopes": [
        "openid",
        "email",
        "profile"
      ],
      "default_scopes": [
        "openid",
        "email"
      ],
      "allowed_token_exchange_targets": [
        "https://api.example.org/"
      ],
      "max_session_ttl_seconds": 28800
    },
    "etl-worker": {
      "desc": "AWS EC2 ETL ingest service (role-based, no shared secret)",
      "adapter": {
        "name": "aws_presigned",
        "role_arn": "arn:aws:iam::123456789012:role/my-etl-role"
      },
      "allowed_grant_types": [
        "client_credentials"
      ],
      "allowed_resources": [
        "https://api.example.org/"
      ],
      "allowed_scopes": [
        "ingest"
      ],
      "default_scopes": [
        "ingest"
      ],
      "max_session_ttl_seconds": 7200,
      "absolute_session_lifetime_seconds": 86400,
      "additional_claims": {
        "name": "ETL Worker Service Account"
      }
    }
  }
}
```

---

## Configuration checklist

- [ ] `CREDENZA_BASE_URL` set to the public HTTPS URL of this deployment
- [ ] `CREDENZA_DEFAULT_REALM` matches a key in `oidc_idp_profiles.json`
- [ ] `oidc_idp_profiles.json` present with at least one realm; `client_secret_file` paths are accessible
- [ ] `client_registry.json` present (may be empty `{"version":"1","clients":{}}` for browser-only deployments)
- [ ] `CREDENZA_STORAGE_BACKEND` set to `redis` or `postgresql` for production multi-worker deployments
- [ ] `CREDENZA_ENABLE_PROXYFIX=true` if running behind a reverse proxy
- [ ] `CREDENZA_ENCRYPT_SESSION_DATA=true` and `CREDENZA_ENCRYPTION_KEY` set if session encryption is required
- [ ] Audit log path writable or syslog configured