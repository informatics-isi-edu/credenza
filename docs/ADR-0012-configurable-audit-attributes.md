# ADR-0012: Configurable Session Attributes in the Audit Log

## 1. Status

**Proposed**
Decision Date: 2026-11-16

### Review History

| Date       | Status   | Notes         |
|------------|----------|---------------|
| 2026-11-16 | Proposed | Initial draft |

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
match ACLs against those principal strings. On FaceBase, the `RasDerivaErmrestSessionAugmentationProvider`
runs three configured ERMrest queries at login and on each upstream refresh. Together they produce
principals such as:

- `tag:facebase.org,2026:role/Registered`
- `tag:facebase.org,2026:role/Curator`
- `tag:facebase.org,2026:dar/1-ABC2`, one per approved Data Access Request

None of these values is written to the audit log. The ERMrest and hatrac request logs record only
the client id (`<iss>/<sub>`), not the session's attributes. Once a session ends, nothing shows
which DARs or roles it held. The same is true across a refresh: a DAR approved or revoked
mid-session changes the attributes, and that change is not recorded either.

The NIH CADR logging standard asks for a `user_permission_group` on each logged event. The RAS
TTX for FaceBase needs a trace from authentication to data access that includes the authorizing
permission. Other deployments will have their own versions of this requirement.

### 2.2 Constraints

- **Credenza is deployment-neutral.** "DAR", `user_permission_group` and the
  `tag:facebase.org,2026:` namespace are FaceBase concepts and CADR vocabulary. Credenza only
  carries opaque principal strings that come from configuration. The audit log must not grow
  fields that encode one deployment's model.
- **The attributes are already config-driven.** Role principals come from
  `session_augmentation_params` in the realm's IdP profile. Claims are read through the realm's
  claim map (`resolve_claim`). A selector over those same claims needs no new concepts.
- **Augmentation can be deferred.** With `defer_augmentation: true`, which FaceBase needs because
  its role queries use the new session key, `augment_session` runs after the `login` event has
  been written (`rest/login.py:227` and `:232-235`; `rest/device.py:310` and `:332-335`). The
  attributes therefore do not exist yet when the identity snapshot is taken.
- **Attributes change during a session.** `PUT /session` with an upstream refresh calls the
  provider's `enrich_userinfo` again (`rest/session.py:186-188`). The role set can differ before
  and after that call.
- **Volume and PII.** The snapshot rule writes personal information once per authentication, and
  `CREDENZA_AUDIT_INCLUDE_PII` can turn it off. Attribute logging should follow the same
  discipline: write values when they are established or change, not on every event.

---

## 3. Decision

Add a per-realm `audit_attributes` selector to the IdP profile. Add a new audit event,
`session_attributes`, that records the selected values when augmentation establishes them and
again whenever they change.

### 3.1 Configuration

`audit_attributes` is an optional list in a realm's entry in `oidc_idp_profiles.json`. It sits
beside `session_augmentation_params`, so the queries that produce the attributes and the selector
that logs them are configured in one place. A realm without the key emits no
`session_attributes` events, which is today's behaviour.

```json
"audit_attributes": [
  {
    "field": "user_permission_group",
    "claim": "roles",
    "select": "id",
    "match": "^tag:facebase\\.org,2026:(dar/.+)$",
    "emit": "\\1"
  },
  {
    "field": "user_roles",
    "claim": "roles",
    "select": "id",
    "match": "^tag:facebase\\.org,2026:(role/.+)$",
    "emit": "\\1"
  }
]
```

Each entry selects one output field.

| Key          | Required | Meaning                                                                                                                                                                                                                                       |
|--------------|----------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `field`      | yes      | Output key. Must match `^[A-Za-z_][A-Za-z0-9_]{0,63}$` and be unique within the realm. The deployment chooses the name, so FaceBase can use the CADR name `user_permission_group` without Credenza knowing it.                                  |
| `claim`      | yes      | Canonical claim name, resolved with `resolve_claim(..., listify=True)` against the realm's claim map. This is the same resolution `make_session_response` uses to build the session's attributes.                                                |
| `select`     | no       | For dict-valued entries, which key to log: `id` (the default) or `display_name`. String entries are used as they are. Any other type is skipped.                                                                                               |
| `match`      | no       | Regular expression. Only values it matches (`re.fullmatch`) are kept. If absent, every value is kept.                                                                                                                                         |
| `emit`       | no       | Replacement template applied to the match (`Match.expand`), e.g. `\1` to log `dar/1-ABC2` in place of the full tag URI. Requires `match`. If absent, the whole value is logged.                                                               |
| `pii`        | no       | `true` if the values identify a person. Such fields are omitted when `CREDENZA_AUDIT_INCLUDE_PII` is false. Defaults to `false`; role and permission principals are not personal information.                                                  |
| `max_values` | no       | Cap on the number of values logged for the field. Defaults to 100. When the cap is hit, the record includes `truncated: [<field>, ...]`.                                                                                                       |

The output is a sorted, de-duplicated list of strings, each cut to 256 characters. A selector
never logs a nested object.

The profile is validated at startup, and a malformed `audit_attributes` block stops startup. The
checks: required keys are present, `field` names are valid and unique, each `match` compiles, and
each `emit` only references groups its `match` defines. A selector that is silently ignored would
leave an audit gap nobody notices until an investigation.

### 3.2 The `session_attributes` Event

```json
{
  "event": "session_attributes",
  "timestamp": "2026-11-16T10:42:07.118-08:00",
  "client_ip": "203.0.113.7",
  "session_id": "0b6c...",
  "iss": "https://sts.nih.gov",
  "sub": "...",
  "identity": "https://sts.nih.gov/...",
  "realm": "nih-ras",
  "trigger": "login",
  "complete": true,
  "attributes": {
    "user_permission_group": ["dar/1-ABC2", "dar/1-DEF4"],
    "user_roles": ["role/Registered"]
  },
  "added":   {"user_permission_group": ["dar/1-ABC2", "dar/1-DEF4"], "user_roles": ["role/Registered"]},
  "removed": {}
}
```

- **Identifiers.** The record carries `audit_identity()` (`iss`, `sub`, `identity`), not the
  snapshot, and joins to the snapshot through `session_id`. That follows the existing rule that
  personal information is written once per authentication.
- **`attributes`** holds the full selected set after the change. A reader can tell what the
  session held from the latest record alone, without replaying a series of diffs.
- **`added` and `removed`** hold the per-field difference from the previous selected set. At
  login, everything is `added`.
- **Nesting.** The deployment-named fields are nested under `attributes`. They cannot collide
  with Credenza's own top-level fields, so Credenza's schema stays fixed. A log shipper that wants
  them at the top level (for Splunk CIM names) can flatten `attributes.*` at ingest.
- **`trigger`** is one of `login`, `device_login` or `refresh`, and records which path ran the
  augmentation.
- **`complete`** is the provider's `enrich_userinfo` return value. `false` means at least one
  source failed, for example an ERMrest role query timed out. An empty or short `attributes`
  list then means "not known", not "held nothing", and an investigator has to be able to tell
  the difference.

### 3.3 When It Is Emitted

- **Login and device login.** The event is written once augmentation has run and the session id
  exists. On the deferred path this is directly after the deferred `augment_session` call
  (`rest/login.py:234`, `rest/device.py:334`). On the non-deferred path it is directly after
  the `login` / `device_login` event. If the selected set is empty, the event is still written at
  login: "held nothing" is a fact worth recording.
- **Refresh.** In `PUT /session`, the selected set is computed before and after
  `enrich_userinfo` (`rest/session.py:186-188`). Both sets come from the in-memory userinfo
  within the same request, so nothing new is stored. The event is written only if the two sets
  differ, or if `complete` changed. A refresh that changes nothing writes nothing; the existing
  `session_updated` event already records that the refresh happened.
- **Logout and expiry.** No event is written. The session's last `session_attributes` record
  stands until the existing `logout` or expiry event closes the session.

### 3.4 Investigation Join

A request log line carries `session_id` once Credenza's session response sets webauthn2's
`tracking` field to the session id. That change is tracked separately in the RAS TTX gap analysis.
With it in place:

1. ERMrest/hatrac record (time T, `track` = `session_id`)
2. → `login` (`txn`, identity snapshot)
3. → the latest `session_attributes` for that `session_id` with timestamp ≤ T: the permissions
   the session held when the request was made.

This shows which DARs and roles the session held. It does not show which of them ERMrest matched
for a given request. That would need ERMrest to log the ACL decision, and it is out of scope.

---

## 4. Working Decisions

- **Per-realm, not global.** Claim maps, augmentation providers and role queries are all per
  realm. The selector lives with them, and a global `CREDENZA_AUDIT_ATTRIBUTES` setting is not
  added.
- **A separate event, not a field on `login`.** With deferred augmentation, `login` is written
  before the attributes exist. Mid-session changes need an event of their own in any case.
- **No static or constant fields.** Values like `nih_ico` or `cadr_name` do not vary by session.
  They belong in the log shipper or the SIEM ingest configuration, not in Credenza.
- **`acr` and `user_agent` are not selector material.** They are generic OIDC and HTTP facts and
  belong in Credenza's fixed schema. Adding them to the `login` event is a separate small change.
- **The selector reads userinfo claims only.** It never reads tokens, `additional_tokens` or
  session metadata.

---

## 5. Open Questions

1. **Step-up roles (ADR-0011).** Assumed roles have their own audit events (`role_assumed`,
   `role_dropped`, ...). If ADR-0011 stores assumed roles outside the augmented `roles` claim,
   the selector will not see them. An investigator then reads permissions from two event types.
   Decide whether `session_attributes` should also be written on assumption and drop, with
   `trigger: role_assumed` / `role_dropped`, so that one event type carries the whole picture.
2. **Derived sessions (token exchange).** A DERIVED session inherits its parent's userinfo. Should
   its creation write a `session_attributes` record of its own, or is the parent's record enough,
   given the exchange event links the two sessions?
3. **Refresh worker.** The background refresh worker refreshes tokens but does not re-run
   augmentation, so it writes no `session_attributes` events. That is consistent with this design,
   but a deployment relying on long device sessions should know that attribute changes appear only
   on `PUT /session` refresh or at the next login.
4. **Value cap default.** 100 values per field is a guess. A user with many approved DARs could
   exceed it, and the right default depends on observed role counts.

---

## 6. Consequences

- A deployment can record the permission set of every session, and every change to it, without
  Credenza knowing what the permissions mean. FaceBase gets `user_permission_group` for the CADR
  logging table, and other deployments can select their own claims.
- The audit schema gains one event type with a fixed shape. Deployment-specific names stay inside
  `attributes`.
- Audit volume grows by one record per login, plus one per refresh that changes the selection.
  On FaceBase, a change means a DAR approval, a revocation or a role edit, so this is small.
- `docs/audit-events.md` and `docs/configuration.md` need sections for the event and the profile
  key, and the profile loader gains validation.
- Misconfiguration stops startup instead of degrading silently, so a broken selector is found at
  deploy time, not during an incident.
