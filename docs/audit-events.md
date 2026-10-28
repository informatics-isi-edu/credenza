# Credenza Audit Events

Credenza writes one structured JSON record per audit event, to syslog (facility `local1`,
ident `credenza-audit`) or to stderr. This document describes the fields those records carry,
how subjects are identified, and when personal information is recorded.

## Common fields

| Field        | Present                    | Meaning                                                              |
|--------------|----------------------------|----------------------------------------------------------------------|
| `event`      | always                     | Event type, e.g. `login`, `logout`, `access_token_refreshed`.        |
| `timestamp`  | always                     | ISO 8601 local time with UTC offset.                                 |
| `client_ip`  | when handling a request    | Client address as seen by Credenza (see `CREDENZA_ENABLE_PROXYFIX`). |
| `session_id` | events about a session     | Credenza session id. Joins every event in a session's life.          |
| `realm`      | events about a session/IdP | Configured IdP profile name. A local alias, not an identifier.       |
| `txn`        | when the IdP supplies one  | IdP transaction id from the access token (NIH RAS).                  |

Event-specific fields (scopes, resources, `client_id` of the OAuth client, error details, and so
on) follow these.

## Subject identifiers

Every event about an authenticated subject carries three identifier fields:

| Field      | Meaning                                                                              |
|------------|--------------------------------------------------------------------------------------|
| `iss`      | Issuer of the subject's identity (the IdP). `null` for service (M2M) subjects.       |
| `sub`      | Subject identifier, unique only within `iss`.                                        |
| `identity` | `<iss>/<sub>`, or the bare `sub` when there is no issuer.                            |

`sub` alone does not identify anyone: two IdPs can issue the same `sub` to different people, and
`realm` is a configuration alias that can be renamed or repointed. `iss` is therefore always
recorded with `sub`.

`identity` is formed exactly as `GET /session` forms the client id, which is also the id ERMrest
records for the client in `ERMrest_client.ID` and in row provenance (`RCB`/`RMB`). Audit records
join directly to catalog records on this value.

The values are resolved through the realm's claim map, so IdPs that name these claims differently
are handled the same way as session rendering.

The OAuth `client_id` field, where present, names the registered OAuth client making the request,
not the subject.

## Identity snapshot

An event carries an identity snapshot when it records the outcome of an authentication at the IdP,
whether Credenza accepted or rejected the result. The snapshot holds the identifying attributes the
IdP asserted in that authentication.

| Field                | Meaning                                                                                                                                                                                                               |
|----------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `preferred_username` | IdP username. For NIH RAS this is an opaque `<uuid>@login.gov` style id.                                                                                                                                              |
| `full_name`          | Display name.                                                                                                                                                                                                         |
| `email`              | Email address as asserted by the IdP; not necessarily verified.                                                                                                                                                       |
| `email_verified`     | The IdP's verification flag, when supplied.                                                                                                                                                                           |
| `identities`         | Sorted list of linked identity ids from the realm's augmentation provider: `<iss>/<sub>` for Globus linked identities, the source `identity_username` for RAS federated identities. Empty when the IdP supplies none. |

Events carrying the snapshot:

- `login`
- `device_login`
- `session_from_bearer_token`
- `login_acr_rejected`
- `device_login_acr_rejected`

All other events carry only the subject identifiers and join back to the snapshot through
`session_id`. Personal information is therefore written once per authentication rather than on
every refresh, introspection or logout.

The snapshot records values as of authentication. Users change names and email addresses, and a
person who moves between institutions may have several accounts; the snapshot preserves what was
asserted for each session, which a registry of current values cannot.

### Step-up authentication

Role assumption (ADR-0011, not yet implemented) re-authenticates an existing session's subject at
the IdP before granting a time-boxed role. That re-authentication creates no session, but it is an
authentication outcome, so the same rule applies:

| Event                                                                          | Snapshot             |
|--------------------------------------------------------------------------------|----------------------|
| `role_assumption_requested`                                                    | no                   |
| `role_assumption_denied` before the IdP round trip (role not eligible)         | no                   |
| `role_assumed`                                                                 | yes                  |
| `role_assumption_denied` after the callback (stale `auth_time`, insufficient `acr`, role no longer eligible) | yes |
| `role_assumption_denied` with `failed_check: subject_mismatch`                 | yes, both identities |
| `role_assumption_expired`, `role_dropped`                                      | no                   |

On a subject mismatch, a different subject completed the step-up than the one that owns the
session. The record carries the session's subject in the standard `iss`, `sub` and `identity`
fields, so it joins like every other event, and the subject that actually authenticated in a
nested `presented` object holding its identifiers and snapshot:

```json
{
  "event": "role_assumption_denied",
  "session_id": "6a53fd87-f029-41a7-9982-84b240617697",
  "iss": "https://idp.example.org",
  "sub": "abc123",
  "identity": "https://idp.example.org/abc123",
  "realm": "example",
  "role": "https://example.org/roles/curator",
  "failed_check": "subject_mismatch",
  "presented": {
    "iss": "https://idp.example.org",
    "sub": "def456",
    "identity": "https://idp.example.org/def456",
    "preferred_username": "bob",
    "full_name": "Bob Example",
    "email": "bob@example.org",
    "email_verified": true,
    "identities": []
  },
  "auth_time": 1761675935,
  "acr": "https://example.org/assurance/aal2"
}
```

`role_assumed` and every post-callback `role_assumption_denied` also record the evidence of the
re-authentication: `auth_time`, `acr`, `amr` when the IdP supplies it, and `txn`. These are not
personal information and are recorded whatever `CREDENZA_AUDIT_INCLUDE_PII` is set to.

### Disabling the snapshot

`CREDENZA_AUDIT_INCLUDE_PII` (default `true`) controls the snapshot. When `false`, the snapshot
events carry only `iss`, `sub` and `identity` (and a `presented` object holds only those three),
and the audit log contains no names or email addresses. Identifying a person then requires resolving identifiers against an external registry
such as `ERMrest_client`.

With the snapshot enabled, the audit log contains personally identifiable information. Access to
the log, its retention period and its handling once forwarded to an aggregator need to be set
accordingly.

## What Credenza can and cannot see

Credenza is a relying party: users authenticate at the IdP. A failed password, MFA failure or
abandoned login at the IdP never reaches Credenza and produces no Credenza audit record. Credenza
records only what returns to its callback:

- successful authentications (`login`, `device_login`);
- authentications Credenza rejects after the IdP succeeded (`login_acr_rejected`,
  `device_login_acr_rejected`, and post-callback `role_assumption_denied` once step-up exists);
- callback failures with no validated identity (state, nonce or token validation errors), which
  carry no subject fields.

A complete record of attempted logins for a subject therefore needs the IdP's own logs as well.

## Example

Field values are illustrative.

```json
{
  "event": "login",
  "timestamp": "2026-10-28T11:25:35.109849-07:00",
  "client_ip": "198.51.100.10",
  "session_id": "6a53fd87-f029-41a7-9982-84b240617697",
  "iss": "https://stsstg.nih.gov",
  "sub": "3nON_ztMzYm4SFDwvVtqrBiYgWNG4YRFwmEF6Au0evU",
  "identity": "https://stsstg.nih.gov/3nON_ztMzYm4SFDwvVtqrBiYgWNG4YRFwmEF6Au0evU",
  "preferred_username": "00000000-0000-0000-0000-000000000000@login.gov",
  "full_name": "Example User",
  "email": "user@example.org",
  "email_verified": null,
  "identities": ["00000000-0000-0000-0000-000000000000@login.gov"],
  "scopes": ["openid", "profile", "federated_identities_ial2", "email"],
  "realm": "nih-ras-staging",
  "txn": "e283775edf3dff76.355374a01c8bfa1b"
}
```

A later event in the same session carries identifiers only:

```json
{
  "event": "logout",
  "timestamp": "2026-10-28T12:02:11.004211-07:00",
  "client_ip": "198.51.100.10",
  "session_id": "6a53fd87-f029-41a7-9982-84b240617697",
  "iss": "https://stsstg.nih.gov",
  "sub": "3nON_ztMzYm4SFDwvVtqrBiYgWNG4YRFwmEF6Au0evU",
  "identity": "https://stsstg.nih.gov/3nON_ztMzYm4SFDwvVtqrBiYgWNG4YRFwmEF6Au0evU",
  "realm": "nih-ras-staging"
}
```
