# ADR-0011: Step-Up Role Assumption for Privileged Roles

## 1. Status

**Proposed**
Decision Date: 2026-10-20

### Review History

| Date       | Status   | Notes         |
|------------|----------|---------------|
| 2026-10-20 | Proposed | Initial draft |

---

## 2. Context

### 2.1 Roles from ERMrest

A DERIVA deployment can keep its role assignments in its own ERMrest catalog rather than in an
external groups service. Two tables in the catalog's `public` schema hold them:

- `role`: a vocabulary of named roles (`Admin`, `Curator`, `Member`, ...) with a unique `Name`,
  a `Description`, and a boolean `Manual_Assume`.
- `ERMrest_Client_role`: binds an `ERMrest_Client.ID` (the user's `<iss>/<sub>` client id) to a
  role `Name`.

Credenza's `DerivaErmrestSessionAugmentationProvider` reads these at login and on each upstream
refresh, using the user's own session key, and adds each returned role to the session's `roles`
as a principal string such as `tag:example.org,2026:role/Member`. ERMrest then matches ACLs
against those strings.

### 2.2 The Problem

`Manual_Assume` marks roles that must not be active by default. A user bound to `Admin` or
`Curator` should browse, download and work with their own data as an ordinary user, and hold the
privileged role only for the stretch of work that needs it, after deliberately taking it on. This
is standard least-privilege practice, and compliance regimes expect it: privileged
functions are used from a deliberately elevated context, the elevation is authenticated afresh,
and both the elevation and its use are auditable (NIST 800-53 AC-6(1), AC-6(2), AC-6(9), IA-11).

The augmentation provider cannot express this. It grants every row its queries return, for the
whole life of the session. The configured query therefore filters `Manual_Assume=false`, so
manually assumed roles currently reach no session at all: staff can be bound to `Admin` in the
catalog but have no way to exercise it through Credenza.

### 2.3 Constraints from the Existing Design

- **`/login` short-circuits for an existing session** (`rest/login.py`): it redirects straight to
  the referrer. Re-authentication of a logged-in user needs a separate entry point.
- **The callback creates a new session.** A step-up must instead modify the existing one, and
  must prove the person re-authenticating is the session's subject.
- **Token exchange copies `userinfo`** into the derived session (`rest/token.py`). Anything
  stored in `userinfo` propagates to every DERIVED session (for example an MCP server acting for
  the user). Elevated roles must not propagate that way.
- **Augmentation rewrites its own entries** in `userinfo` on each run. Assumed roles have a
  different lifecycle and must not be mixed into that bookkeeping.
- **Only the authenticated subject is an ACL principal.** Linked identities never confer roles;
  that holds for assumed roles too.

---

## 3. Decision

Add **role assumption**: an authenticated user may take on a role they are bound to with
`Manual_Assume=true`, for a bounded time, in the current session only, after a fresh
re-authentication at the upstream IdP.

### 3.1 Eligibility

A realm's `session_augmentation_params` gains `ermrest_assumable_role_queries`, a list with the
same shape as `ermrest_role_queries` (URL template restricted to `{client_id}`, `{iss}`,
`{sub}`; `id` and `display_name` templates over result columns; `claim`). With the tables above
it is the assigned-roles query with the filter inverted:

```
/ermrest/catalog/1/attribute/public:ERMrest_Client_role/ERMrest_Client={client_id}/public:role/Manual_Assume=true/Name,Description
```

The rendered ids are the roles the user may assume. Credenza never accepts a role id from the
client that it did not render from these queries itself, so eligibility is decided by the
catalog, under the catalog's ACLs, queried with the user's own credential.

### 3.2 Flow

1. The client (Chaise, a browser) sends the user to
   `GET /assume?role=<role id>&referrer=<url>`.
2. Credenza requires an existing USER session, runs the assumable-role queries, and rejects the
   request if `role` is not among the results.
3. Credenza starts an authorization request to the session's own realm with `prompt=login` and
   `max_age=0`, recording in the authn request context: the session id, the requested role, the
   request time, and the referrer.
4. The callback recognises the step-up context and, instead of creating a session:
   - validates the ID token as usual (signature, nonce, PKCE);
   - requires `iss` and `sub` to equal the session's;
   - requires `auth_time` to be no earlier than the request time recorded in step 3;
   - applies the realm's `required_acr` (or a stricter `step_up_required_acr`, if configured);
   - re-runs the assumable-role queries and confirms the role is still eligible;
   - adds the role to the session's assumed roles with an expiry, and redirects to the referrer.

Any failed check leaves the session unchanged and is audited.

### 3.3 Storage and Rendering

Assumed roles live in a new `SessionData` field, `assumed_roles`, a map of role id to
`{display_name, claim, assumed_at, expires_at, auth_time}`. They are not written into `userinfo`.
`make_session_response` (both legacy and modern shapes) and `/introspect` merge unexpired
assumed roles into the rendered `roles`/`groups` at render time, and the legacy response
therefore includes them in `attributes`, where ERMrest sees them.

Token exchange does not copy `assumed_roles`: a DERIVED session never carries an elevation.

### 3.4 Lifetime and Revocation

- **Expiry.** Each assumption expires after `role_assumption_ttl` seconds (default 3600,
  configurable per realm), and never later than the session itself. It is not extended by
  `PUT /session`. Renewing it means repeating the step-up.
- **Re-validation.** Whenever augmentation runs, the assumable-role queries run too, and any
  assumed role no longer eligible is dropped. If they fail, all assumed roles are dropped (fail
  closed, as for ordinary role mapping).
- **Explicit drop.** `DELETE /assume?role=<role id>` (or with no `role`, all) drops assumptions
  immediately. Logout drops everything with the session.

### 3.5 Audit

New audit events, each carrying session id, sub, realm, role id and the IdP `txn` where present:
`role_assumption_requested`, `role_assumed` (with `auth_time` and `expires_at`),
`role_assumption_denied` (with the failed check), `role_assumption_expired` (logged when an
expired assumption is first observed), and `role_dropped` (explicit, revalidation, or logout).

---

## 4. Working Decisions

- **Endpoint names** `GET /assume` / `DELETE /assume` are placeholders. An alternative is a
  resource under `/session` (`/session/roles/...`), which would sit naturally beside the
  session response but makes the browser redirect flow less obvious.
- **Default lifetime** of one hour is a placeholder; deployments are expected to set their own.
- **Scope of an assumption** is the whole session: every resource server the session reaches
  sees the role. Per-resource assumptions are not proposed.
- **A listing endpoint** (`GET /assume`, returning assumable roles without starting a flow) is
  probably needed for Chaise to render an "assume role" menu; it would only run the queries.

---

## 5. Open Questions

1. **Does RAS honour `prompt=login` and `max_age=0`?** The whole mechanism depends on the IdP
   performing a fresh authentication and reporting it in `auth_time`. RAS returns `auth_time`
   in its ID tokens (observed on staging), but whether it forces re-authentication on these
   parameters, or silently reuses its own SSO session, has not been tested. If it reuses the
   SSO session, `auth_time` will predate the request and Credenza will (correctly) refuse every
   step-up. This must be verified against RAS staging before implementation.
2. **Device-flow sessions.** deriva-py sessions come from the device flow and have no browser
   attached to the session. A device-flow step-up variant (a second device authorization bound
   to the existing session) is possible but not designed here. Until then, assumption is
   browser-only.
3. **Chaise integration.** Chaise needs a way to offer and display assumed roles, and to send
   the user through `/assume`. That is client work outside Credenza.
4. **ERMrest caching of session attributes.** If any resource server caches the session's
   attributes, an expiry or drop takes effect only when that cache refreshes. The effective
   revocation latency needs to be confirmed for ERMrest and hatrac.

---

## 6. Consequences

- Privileged catalog roles become usable through Credenza without being standing grants.
- Each elevation is tied to a fresh, audited authentication at the IdP, giving deployments direct
  evidence for their least-privilege and re-authentication controls.
- The session gains a second source of roles with its own lifecycle; rendering, introspection
  and token exchange all have to respect the split, and tests must cover each.
- The feature depends on IdP behaviour (open question 1) that Credenza cannot enforce, only
  verify. If RAS does not support forced re-authentication, this design cannot ship as written.
