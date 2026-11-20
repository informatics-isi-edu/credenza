# ADR-0012: Configurable Session Attributes in the Audit Log

## 1. Status

**Accepted**
Decision Date: 2026-11-19

### Review History

| Date       | Status   | Notes                                                                                               |
|------------|----------|-----------------------------------------------------------------------------------------------------|
| 2026-11-16 | Proposed | Initial draft                                                                                       |
| 2026-11-19 | Accepted | Implemented on `ras_compat` (`af7d8b7`); `complete` / `failed_sources` and the refresh trigger revised to match |

---

## 2. Context

### 2.1 The Problem

An investigation of a data access has to answer two questions about the session that made the
request: who the user was, and what the user was permitted to reach at that moment. Credenza's
audit log answers the first. Each authentication writes an identity snapshot (`login`,
`device_login`, and the other snapshot events in `docs/audit-events.md`), and every other event
joins back to it through `session_id`. The log does not answer the second question.

In DERIVA deployments, permissions reach the resource servers as session attributes. The realm's
augmentation provider adds groups and roles to the session's userinfo, and ERMrest and hatrac
match ACLs against those principal strings. For example, `DerivaErmrestSessionAugmentationProvider`
runs configured ERMrest queries at login and whenever augmentation re-runs, and adds principals such as
`tag:example.org,2026:role/Curator` or `tag:example.org,2026:grant/1-ABC2`.

None of these values is written to the audit log. The ERMrest and hatrac request logs record only
the client id (`<iss>/<sub>`), not the session's attributes. Once a session ends, nothing shows
which roles or grants it held. The same is true across a refresh: an access grant added or revoked
mid-session changes the attributes, and that change is not recorded either.

Deployments that must report a user's permission group per logged event, or that must reconstruct
an authorization trail during an incident, need these values in the audit log.

### 2.2 Constraints

- **Credenza is deployment-neutral.** A role or grant principal is an opaque string that comes from
  a deployment's configuration. Credenza does not know what it means, what the deployment calls it
  in its own reporting, or which namespace it belongs to. The audit log must not gain fields named
  after one deployment's model.
- **The attributes are already config-driven.** Role principals come from
  `session_augmentation_params` in the realm's IdP profile. Claims are read through the realm's
  claim map (`resolve_claim`). A selector over those same claims needs no new concepts.
- **Augmentation can be deferred.** Some providers look up the user's roles by querying a resource
  server with the user's own Credenza session key. That key only exists once the session has been
  created, so these providers set `defer_augmentation: true`, and their lookup runs after the
  session is created and the `login` event has been written. The `login` event, and the identity
  snapshot it carries, therefore cannot include the roles.
- **Attributes change during a session.** Augmentation re-runs after the background worker
  refreshes a device session's tokens, and on an explicit `PUT /session?refresh_upstream=true`.
  The role set can differ before and after.
- **Volume and PII.** The audit log writes a user's personal information (name, email) only once
  per authentication, on the login event, and `CREDENZA_AUDIT_INCLUDE_PII` can turn even that off.
  Attribute logging should be equally sparing: write the values when they are first established
  and when they change, not on every event.

---

## 3. Decision

Add a per-realm `audit_attributes` selector to the IdP profile. Add a new audit event,
`session_attributes_updated`, that records the selected values when augmentation establishes them and
again whenever they change.

### 3.1 Configuration

`audit_attributes` is an optional list in a realm's entry in `oidc_idp_profiles.json`. It sits
beside `session_augmentation_params`, so the queries that produce the attributes and the selector
that logs them are configured in one place. A realm without the key emits no
`session_attributes_updated` events.

```json
"audit_attributes": [
  {
    "field": "permissions",
    "claim": "roles",
    "select": "id",
    "match": "^tag:example\\.org,2026:(grant/.+)$",
    "emit": "\\1"
  },
  {
    "field": "user_roles",
    "claim": "roles",
    "select": "id",
    "match": "^tag:example\\.org,2026:(role/.+)$",
    "emit": "\\1"
  }
]
```

Each entry selects one output field.

| Key          | Required | Meaning                                                                                                                                                                                         |
|--------------|----------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `field`      | yes      | Output key. Must match `^[A-Za-z_][A-Za-z0-9_]{0,63}$` and be unique within the realm. The deployment chooses the name, so it can use its own reporting vocabulary without Credenza knowing it. |
| `claim`      | yes      | Canonical claim name, resolved with `resolve_claim(..., listify=True)` against the realm's claim map. This is the same resolution the session response uses to build the session's attributes.  |
| `select`     | no       | For dict-valued entries, which key to log: `id` (the default) or `display_name`. String entries are used as they are. Any other type is skipped.                                                |
| `match`      | no       | Regular expression. Only values it matches (`re.fullmatch`) are kept. If absent, every value is kept.                                                                                           |
| `emit`       | no       | Replacement template applied to the match (`Match.expand`), e.g. `\1` to log `grant/1-ABC2` in place of the full tag URI. Requires `match`. If absent, the whole value is logged.               |
| `pii`        | no       | `true` if the values identify a person. Such fields are omitted when `CREDENZA_AUDIT_INCLUDE_PII` is false. Defaults to `false`; role and permission principals are not personal information.   |
| `max_values` | no       | Cap on the number of values logged for the field. Defaults to 100. When the cap is hit, the record includes `truncated: [<field>, ...]`.                                                        |

The output is a sorted, de-duplicated list of strings, each cut to 256 characters. A selector
never logs a nested object.

The profile is validated at startup, and a malformed `audit_attributes` block stops startup. The
checks: no unknown keys, required keys are present, `field` names are valid and unique, each
`match` compiles, each `emit` only references groups its `match` defines, `pii` is a boolean and
`max_values` a positive integer. A selector that is silently ignored would leave an audit gap
nobody notices until an investigation.

### 3.2 The `session_attributes_updated` Event

```json
{
  "event": "session_attributes_updated",
  "timestamp": "2026-11-16T10:42:07.118-08:00",
  "client_ip": "203.0.113.7",
  "user_agent": "Mozilla/5.0 ...",
  "session_id": "0b6c...",
  "iss": "https://idp.example.org",
  "sub": "...",
  "identity": "https://idp.example.org/...",
  "realm": "example",
  "trigger": "login",
  "complete": true,
  "attributes": {
    "permissions": ["grant/1-ABC2", "grant/1-DEF4"],
    "user_roles": ["role/Member"]
  },
  "added":   {"permissions": ["grant/1-ABC2", "grant/1-DEF4"], "user_roles": ["role/Member"]},
  "removed": {}
}
```

- **Identifiers.** The record identifies the user only by `iss`, `sub` and `identity`. The name and
  email stay on the login event, which the record joins to through `session_id`. Personal
  information is still written only once per authentication.
- **`attributes`** holds the complete selection as of this record. A reader can tell what the
  session held from the latest record alone, without replaying earlier ones.
- **`added` and `removed`** hold the per-field difference from the previous selected set. At
  login, everything is `added`.
- **Nesting.** The deployment-named fields are nested under `attributes`. They cannot collide
  with Credenza's own top-level fields, so Credenza's schema stays fixed. A log shipper that wants
  them at the top level can flatten `attributes.*` at ingest.
- **`trigger`** is `login`, `device_login` or `refresh`: the operation that produced the
  selection.
- **`complete` and `failed_sources`.** An augmentation provider may draw on several sources, for
  example several role queries. When one of them fails (a query times out, say), the event sets
  `complete` to `false` and lists the failed sources in `failed_sources`. Without this, an
  investigator could not tell an empty selection that means "this user held nothing" from one
  that means "the lookup failed".
- **Provider contract.** `enrich_userinfo` returns an `EnrichmentResult`: `enriched` (some source
  added data) and `failed_sources` (the sources it attempted that failed). A provider that composes
  another through `super()` merges the inherited result into its own. `augment_session` returns
  the result to its caller, which passes it to the audit call. Providers never keep per-call
  outcomes on the instance, because one provider instance serves every request thread.

### 3.3 When It Is Emitted

- **Login and device login.** The event is written once per login, after the `login` /
  `device_login` event. By then the session exists and augmentation has finished, including any
  deferred lookup. The event is written even when nothing is selected, because "held nothing" is
  worth recording.
- **Refresh.** Augmentation re-runs after the refresh worker refreshes a device session's tokens,
  and on an explicit `PUT /session?refresh_upstream=true`. Credenza computes the selection just
  before and just after, so nothing extra is stored. The event is written only if the selection
  changed or a source failed. A re-run that changes nothing writes nothing.
- **Logout and expiry.** No event is written. The session's last `session_attributes_updated` record
  stands until the session ends.

### 3.4 Investigation Join

A resource-server request log line carries `session_id` when the server records Credenza's
session `tracking` value (ERMrest and hatrac log it as `track`). With that:

1. Request record (time T, `track` = `session_id`)
2. → `login` (IdP transaction id where supplied, identity snapshot)
3. → the latest `session_attributes_updated` for that `session_id` with timestamp ≤ T: the permissions
   the session held when the request was made.

This shows which roles and grants the session held. It does not show which of them the resource
server matched for a given request. That would need the resource server to log its ACL decision,
and it is out of scope.

---

## 4. Working Decisions

- **Per-realm, not global.** Claim maps, augmentation providers and role queries are all per
  realm. The selector lives with them, and a global `CREDENZA_AUDIT_ATTRIBUTES` setting is not
  added.
- **A separate event, not a field on `login`.** With deferred augmentation, `login` is written
  before the attributes exist. Mid-session changes need an event of their own in any case.
- **No static or constant fields.** Values that do not vary by session belong in the log shipper or
  the SIEM ingest configuration, not in Credenza.
- **`acr` and `user_agent` are not selector material.** They are generic OIDC and HTTP facts and
  are fixed fields of Credenza's schema.
- **The selector reads userinfo claims only.** It never reads tokens, `additional_tokens` or
  session metadata.

---

## 5. Open Questions

1. **Step-up roles (ADR-0011).** Assumed roles have their own audit events (`role_assumed`,
   `role_dropped`, ...). If ADR-0011 stores assumed roles outside the augmented `roles` claim,
   the selector will not see them. An investigator then reads permissions from two event types.
   Decide whether `session_attributes_updated` should also be written when a role is assumed or dropped,
   with `trigger: role_assumed` / `role_dropped`, so that one event type carries the whole picture.
2. **Derived sessions (token exchange).** A DERIVED session inherits its parent's userinfo. Should
   its creation write a `session_attributes_updated` record of its own, or is the parent's record enough,
   given the exchange event links the two sessions?
3. **Sessions without automatic refresh.** The refresh worker re-runs augmentation only for
   device sessions it refreshes. A device session that did not opt into automatic refresh picks up
   attribute changes only on an explicit `refresh_upstream=true` or at its next login.
4. **Value cap default.** 100 values per field is a guess; the right default depends on observed
   role counts.

---

## 6. Consequences

- A deployment can record the permission set of every session, and every change to it, without
  Credenza knowing what the permissions mean.
- The audit schema gains one event type with a fixed shape. Deployment-specific names stay inside
  `attributes`.
- Audit volume grows by one record per login, plus one per refresh that changes the selection or
  hits a failed source.
- `docs/audit-events.md` and `docs/configuration.md` document the event and the profile key, and
  the profile loader validates it.
- Misconfiguration stops startup instead of degrading silently, so a broken selector is found at
  deploy time, not during an incident.
