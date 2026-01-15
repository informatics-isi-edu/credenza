# Service Auth / M2M in Credenza

## 1. Overview

Credenza supports **service (or machine-to-machine, M2M) authentication** by issuing opaque “service access tokens” 
backed by server-side `service` sessions (as opposed to `user` sessions) in the configured session store 
(e.g., Redis/Postgres/memory) backend.

A caller proves its identity by calling an endpoint specific to service token generation, which invokes a _service auth 
adapter_ (e.g., AWS presigned STS proof) to perform authentication. 

Credenza then:

- maps the caller to an internal `ServiceSubject` (`sub`)
- attaches a policy-defined authorization envelope (scopes, audiences, groups, optional email/name)
- persists a service session
- returns an opaque bearer token (`access_token`) that is used for subsequent API calls


## 2. Endpoints

### Issue token

`POST /authn/service/token` (alias: `POST /authn/service-token`)

Requires form field:

- `grant_type=urn:credenza:service:auth`

Adapter-specific fields determine which adapter matches.

Returns JSON:

```json
{"access_token": "<opaque>", "expires_in": <seconds>}
```

### Revoke token

`DELETE /authn/service/token` (alias: `DELETE /authn/service-token`)

Requires `Authorization: Bearer <access_token>`

- Only revokes service sessions

Returns `204 No Content`

## 3. Service token validation model

A service access token is opaque. Credenza authenticates it by:

- Extracting the session key from `Authorization: Bearer ...`
- Looking up the backing session in the session store
- Enforcing service-session constraints (audience presence, renewal policy, etc.)

This model enables:

- instant revocation (`store.delete_session`)
- centralized renewal semantics
- consistent auditing and rate limiting

## 4. Authorization model: scopes and audiences

Service sessions carry:

- `scopes` (OAuth-like space-delimited tokens)
- `userinfo.aud` (audience list)
- `userinfo.groups` (optional group identifiers)
- optional `userinfo.name`, `userinfo.email`

At issuance time:

- Requested `scope` must be a subset of configured allowed scopes
- Requested `audience` values must be a subset of configured allowed audiences
- If `scope` is omitted, `default_scopes` is used (if present)
- If `audience` is omitted, configured `audiences` are used

At runtime (e.g., `/session` access):

- Service sessions are expected to include `aud`
- Misconfigured/missing `aud` can be treated as a hard deny (403)

## 5. Configuration file reference (`service_auth.json`)

The `service_auth` JSON configuration consists of an `adapters` object keyed by a string value indicating the adapter 
type/name. Each _adapter_ object defines per-adapter `bindings` used to map proofs (keyed by fields like AWS role `ARN`, 
`client_id`) to authorization policy. A _binding_ should uniquely identify a principal, its allowed scopes/audiences, and issuance policy.

Example:

```json
{
  "adapters": {
    "aws_presigned": {
      "bindings": [
        {
          "role_arn":         "arn:aws:iam::123456789012:role/etl-prod-role",
          "name":             "ETL Team",
          "email":            "etl-team@example.org",

          "scopes":           ["etl:ingest", "etl:read"],
          "default_scopes":   ["etl:read"],
          "audiences":        ["urn:deriva:rest:service:all"],
          "groups":           ["etl-writers"],

          "max_ttl_seconds":  7200,
          "absolute_lifetime_seconds": 86400
        }
      ]
    },
    "client_secret": {
      "bindings": [
        {
          "client_id":        "etl-legacy",
          "client_secret":    "REDACTED",
          "name":             "ETL Team",
          "email":            "etl-team@example.org",

          "scopes":           ["etl:read"],
          "default_scopes":   ["etl:read"],
          "audiences":        ["urn:deriva:rest:service:all"],
          "groups":           ["etl-readers"],

          "max_ttl_seconds":  3600,
          "absolute_lifetime_seconds": 7200
        }
      ]
    }
  }
}

```

#### Common binding fields

**Identity selector**

- `aws_presigned`: `role_arn` (IAM role ARN derived from STS GetCallerIdentity)
- `client_secret`: `client_id`

**Authorization**

- `scopes` (required): 
  - list of allowed scope tokens
- `default_scopes` (optional): 
  - scopes used if request omits `scope`
- `audiences` (required): 
  - list of allowed audiences
- `groups` (optional): 
  - list of group strings attached to session `userinfo.groups`
- `name` (optional): 
  - friendly label stored in `userinfo.name`
- `email` (optional): 
  - contact label stored in `userinfo.email`

**Issuance policy**

- `max_ttl_seconds` (optional, default `3600`): 
  - Cap for requested TTL (per principal)
- `absolute_lifetime_seconds` (optional, default `84600`): 
  - Hard-stop lifetime: service session cannot exist past `created_at + absolute_lifetime_seconds`.
  Once exceeded: session is deleted; caller must re-issue via `/authn/service/token`.

**Notes**

- If `audiences` is empty/missing for a binding, issuance fails (treated as misconfiguration).
- Requested values are always validated as subsets of allowed values.


## 6. Adapter behavior details

### 6.1 `aws_presigned`

**What the caller sends**

- `subject_token`: a presigned AWS STS GetCallerIdentity URL

The adapter fetches that URL (with retries on transient failures), parses `<Arn>`, derives an IAM role ARN, and matches it against `role_arn` bindings.

**What gets stored**

- `sub`: `urn:credenza:service:auth:aws:<role_arn>`
- `userinfo.aud`: configured audiences
- `userinfo.groups`: configured groups
- `metadata.proof`: includes `type=aws_presigned_gci`, `principal=<role_arn>`, `caller_arn=<sts caller arn>`, `issued_at=<ts>`

### 6.2 `client_secret`

**What the caller sends**

Either:

- `auth_method=client_secret_post` + `client_id`, `client_secret`

Or:

- `Authorization: Basic base64(client_id:client_secret)`

**What gets stored**

- `sub`: `urn:credenza:service:auth:client_secret:<client_id>`
- `userinfo.*` populated from binding
- `metadata.proof`: includes `type=client_secret`, `principal=<client_id>`, `issued_at=<ts>`

## 7. Calling examples

### 7.1 AWS presigned issuance (high assurance)

```bash
curl -sS -X POST https://<credenza>/authn/service/token \
  -d grant_type="urn:credenza:service:auth" \
  -d subject_token="<PRESIGNED_STS_GETCALLERIDENTITY_URL>" \
  -d scope="etl:ingest etl:read" \
  -d audience="urn:deriva:rest:service:all"
```

If you omit `scope`, Credenza uses:

- `default_scopes: ["etl:read"]`

If you omit `audience`, Credenza defaults to:

- `["urn:deriva:rest:service:all"]`

### 7.2 Client secret issuance (fallback / legacy)

```bash
curl -sS -X POST https://<credenza>/authn/service/token \
  -d grant_type="urn:credenza:service:auth" \
  -d auth_method="client_secret_post" \
  -d client_id="etl-legacy" \
  -d client_secret="REDACTED"
```

Or Basic auth:

```bash
curl -sS -X POST https://<credenza>/authn/service/token \
  -H "Authorization: Basic $(printf '%s' 'etl-legacy:REDACTED' | base64)" \
  -d grant_type="urn:credenza:service:auth"
```

### 7.3 Use the token

```bash
TOKEN="$(... | jq -r .access_token)"
curl -H "Authorization: Bearer $TOKEN" https://<credenza>/authn/session?resource=urn:deriva:rest:service:all
```

### 7.4 Revoke the token

```bash
curl -i -X DELETE \
  -H "Authorization: Bearer $TOKEN" \
  https://<credenza>/authn/service/token
```

## 8. Operational and security guidance

- Set audiences narrowly wherever possible. Audience is the primary mechanism to prevent token reuse across services.
- Keep a strong renewal policy by default:
  - `max_ttl_seconds=3600` prevents service keepalive extending beyond 1h from “now”, unless explicitly extended 
    via `PUT /authn/session`
  - `absolute_lifetime_seconds=86400` forces re-issuance at least daily regardless of session extension
- Consider `require_proof_on_extend=true` for highly sensitive principals so that “near expiry” requires re-proof.
