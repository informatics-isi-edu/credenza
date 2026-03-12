# Client Authentication in Credenza

## 1. Overview

Credenza supports **OAuth client authentication** via the `client_credentials` grant
(`POST /token`). This is the primary mechanism for machine-to-machine (M2M) use cases:
background services, ETL pipelines, AWS-hosted workloads, and other non-interactive
principals that need audience-bound access tokens without a human login flow.

Clients authenticate using a configured adapter (client secret or AWS presigned STS)
and receive opaque bearer tokens backed by server-side sessions in the configured
session store. Sessions are validated by resource servers via `POST /introspect`.

All clients are registered in the **client registry** (`client_registry.json`), which
uses the same `ClientRecord` structure as interactive (browser/device) clients. A single
registry entry may authorize both interactive and M2M grant types (e.g.,
`authorization_code` plus `token_exchange` plus `client_credentials`).

---

## 2. Endpoints

### Issue token

`POST /token`

Form-encoded body (adapter-specific fields vary; see Section 5):

```
grant_type=client_credentials
```

Returns JSON:

```json
{"access_token": "<opaque>", "token_type": "Bearer", "expires_in": <seconds>}
```

### Revoke token

`POST /revoke`

RFC 7009 token revocation. Confidential clients must authenticate (basic or post).

Form body:

```
token=<access_token>
client_id=<client_id>
```

Returns HTTP 200 on all outcomes (including unknown tokens).

### Introspect token

`POST /introspect`

RFC 7662. The calling resource server must be a registered client. If it declares
`allowed_introspection_resources`, only tokens carrying a matching resource will
be returned as active.

---

## 3. Token validation model

A client-issued access token is opaque. Resource servers validate it by calling
`POST /introspect`. Credenza:

- looks up the session by the opaque bearer value
- checks expiry
- enforces resource intersection if `resource` param is provided or if the calling
  client declares `allowed_introspection_resources`
- returns a RFC 7662 response including `active`, `sub`, `aud`, `scope`, `exp`, and
  any additional claims stored at issuance

This model provides:

- instant revocation
- centralized expiry enforcement
- consistent auditing

---

## 4. Authorization model: scopes and resources

Client sessions carry:

- `allowed_resources` -- from the `ClientRecord`, narrowed by any explicit request
- `scopes` -- from the `ClientRecord`, narrowed by any explicit request
- `userinfo` -- populated from `additional_claims` at issuance (`name`, `email`,
  `username`, `roles`, etc.)

At issuance time:

- `scope` in the request must be a subset of `allowed_scopes` (if configured)
- `resource` in the request must be a subset of `allowed_resources` (if configured)
- If `scope` is omitted, `default_scopes` is used (if configured)
- If `resource` is omitted, `default_resources` (if configured) or all `allowed_resources` is used

At introspection time:

- `aud` in the response is the session's `allowed_resources`
- Resource intersection is enforced if the caller provides a `resource` param or
  declares `allowed_introspection_resources`

---

## 5. Client registry configuration

Clients are registered in `client_registry.json`. The authoritative `client_id` is
the JSON object key.

### 5.1 Common fields

```json
{
  "my-service-client": {
    "desc": "Human-readable description",
    "enabled": true,
    "public": false,
    "adapter": { ... },
    "allowed_grant_types": ["client_credentials"],
    "allowed_resources": ["urn:example:service:all"],
    "allowed_scopes": ["read", "write"],
    "default_scopes": ["read"],
    "max_session_ttl_seconds": 3600,
    "absolute_session_lifetime_seconds": 86400,
    "additional_claims": {
      "name": "My Service",
      "email": "ops@example.org"
    }
  }
}
```

#### Identity and enablement

- `enabled` (bool, default `true`) -- disabled clients are rejected at all grant endpoints
- `public` (bool, default `false`) -- M2M clients should always be `false` (confidential)

#### Authorization bounds

- `allowed_grant_types` -- must include `"client_credentials"` for M2M issuance;
  short aliases `"token_exchange"` and `"device_code"` are accepted and normalized to
  their full URN forms at registry load time
- `allowed_resources` -- URIs the client may bind tokens to
- `allowed_scopes` -- scope tokens the client may request
- `default_scopes` -- used when `scope` is omitted; must be a subset of `allowed_scopes`
- `default_resources` -- used when `resource` is omitted; must be a subset of `allowed_resources`

#### Additional claims

- `additional_claims` -- arbitrary key/value pairs stored in `session.userinfo` and
  returned via introspection (e.g., `name`, `email`, `username`, `roles`)

#### Session lifetime

- `max_session_ttl_seconds` (default `3600`) -- cap on TTL per issuance
- `absolute_session_lifetime_seconds` (default `86400`) -- hard lifetime; a session
  cannot be extended past `created_at + absolute_session_lifetime_seconds`

#### Introspection gating

- `allowed_introspection_resources` -- if set, this client may only introspect tokens
  whose `allowed_resources` intersects this list; restricts a resource server to
  introspecting only tokens issued for its own resources

#### Token exchange

- `allowed_token_exchange_targets` -- if `token_exchange` is in `allowed_grant_types`,
  this is the allowlist of target resources the client may exchange into; default-deny
  if omitted

### 5.2 Adapter block

The `adapter` block specifies how the client proves its identity at token issuance time.
Adapters implement a common `AdapterInterface` and are registered by name using the
`@register_adapter` decorator. This makes the adapter layer extensible: new authentication
mechanisms (e.g., mTLS, Kubernetes service account tokens, GCP workload identity, SPIFFE
SVIDs) can be added by implementing the interface without modifying core token handler
logic.

Two adapters are built in:

#### `client_secret`

```json
"adapter": {
  "name": "client_secret",
  "client_secret": "PLAINTEXT",
  "client_secret_hash": "bcrypt:$2b$12$..."
}
```

Supports `client_secret_basic` (Authorization header) and `client_secret_post` (form
body). Configure `allowed_auth_methods` on the client record to restrict which are
accepted. Prefer `client_secret_hash` with bcrypt over a plaintext `client_secret`.

#### `aws_presigned`

```json
"adapter": {
  "name": "aws_presigned",
  "role_arn": "arn:aws:iam::123456789012:role/my-service-role"
}
```

The caller submits a presigned AWS STS `GetCallerIdentity` URL as `subject_token`.
The adapter fetches the URL, parses the caller ARN, derives a role ARN, and matches
against the configured `role_arn`. No long-lived shared secrets are distributed.

#### Writing a custom adapter

Implement `AdapterInterface` and decorate with `@register_adapter`:

```python
from credenza.api.auth.client.adapters.adapter import (
    AdapterInterface, AdapterConfig, AdapterResult, AdapterAuthError,
    ProofContext, Subject, register_adapter
)
from dataclasses import dataclass

@dataclass(frozen=True)
class MyAdapterConfig(AdapterConfig):
    my_field: str

@register_adapter
class MyAdapter(AdapterInterface[MyAdapterConfig]):
    ADAPTER_NAME = "my_adapter"
    SUPPORTED_AUTH_METHODS = ("my_auth_method",)

    @classmethod
    def from_dict(cls, config, client_id):
        return cls(MyAdapterConfig(
            client_id=client_id,
            adapter_name=cls.ADAPTER_NAME,
            config_dict=config,
            my_field=config["my_field"],
        ))

    def authenticate(self, proof_context, allowed_methods=None):
        # inspect proof_context.form / proof_context.headers
        # raise AdapterAuthError on failure
        # return AdapterResult(subject=Subject(provider="my_provider", subject_id=...))
        ...
```

Once imported (so the decorator runs), the adapter is available by its `ADAPTER_NAME`
and can be referenced in `client_registry.json` via `"adapter": {"name": "my_adapter", ...}`.

---

## 6. Calling examples

### 6.1 Client secret -- HTTP Basic auth

```bash
curl -sS -X POST https://<credenza>/authn/token \
  -H "Authorization: Basic $(printf '%s' 'my-client:my-secret' | base64)" \
  -d grant_type=client_credentials \
  -d scope="read write" \
  -d resource="urn:example:service:all"
```

### 6.2 Client secret -- form post

```bash
curl -sS -X POST https://<credenza>/authn/token \
  -d grant_type=client_credentials \
  -d client_id=my-client \
  -d client_secret=my-secret \
  -d scope="read" \
  -d resource="urn:example:service:all"
```

### 6.3 AWS presigned issuance

```bash
PRESIGNED_URL="$(aws sts presign-get-caller-identity ...)"

curl -sS -X POST https://<credenza>/authn/token \
  -d grant_type=client_credentials \
  -d subject_token="$PRESIGNED_URL"
```

Scope and resource may be omitted; `default_scopes` and `allowed_resources` are used.

### 6.4 Use the token

```bash
TOKEN="$(curl ... | jq -r .access_token)"
curl -H "Authorization: Bearer $TOKEN" \
  https://<my-resource-server>/api/endpoint
```

The resource server calls `POST /introspect` to validate the token.

### 6.5 Revoke the token

```bash
# HTTP Basic auth
curl -sS -X POST https://<credenza>/authn/revoke \
  -H "Authorization: Basic $(printf '%s' 'my-client:my-secret' | base64)" \
  -d token="$TOKEN"

# Form-post auth
curl -sS -X POST https://<credenza>/authn/revoke \
  -d token="$TOKEN" \
  -d client_id=my-client \
  -d client_secret=my-secret
```

---

## 7. Token exchange for downstream service calls

A confidential client with `token_exchange` in `allowed_grant_types` may exchange a
user-scoped token for a narrowly scoped derived token to call a downstream service.

```bash
curl -sS -X POST https://<credenza>/authn/token \
  -H "Authorization: Basic $(printf '%s' 'my-client:my-secret' | base64)" \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d subject_token="$USER_TOKEN" \
  -d subject_token_type=urn:ietf:params:oauth:token-type:access_token \
  -d resource="urn:example:service:downstream"
```

Rules:

- `allowed_token_exchange_targets` must include the requested `resource` (default-deny)
- Derived sessions are short-lived (capped at 30 minutes), non-refreshable, non-extendable
- Transitive exchange is not allowed

---

## 8. Operational guidance

- Set `allowed_resources` narrowly. Resource binding is the primary mechanism preventing
  token reuse across services.
- Keep `absolute_session_lifetime_seconds` low for sensitive principals to force
  periodic re-authentication.
- Use `allowed_introspection_resources` on resource server client records to prevent
  one resource server from introspecting tokens issued for a different resource server.
- Store client secrets securely (Docker secrets, secret managers); never commit plaintext
  secrets. Prefer `client_secret_hash` with bcrypt over `client_secret`.
- Prefer `aws_presigned` for AWS-hosted workloads to avoid distributing long-lived
  shared secrets entirely.