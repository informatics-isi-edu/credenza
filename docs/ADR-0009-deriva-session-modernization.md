# ADR-0009: Modernizing the DERIVA Session Contract (Retiring `ENABLE_LEGACY_API`)

**Status:** Discussion / Proposed (2026-06-12)

**Related:** [credenza-flow.md](credenza-flow.md) (general auth/session flows),
[security_model.md](security_model.md) (broker model, audience isolation, no token passthrough),
[credenza-oauth-profile.md](credenza-oauth-profile.md), [ADR-0001](ADR-0001-narrow-oauth-profile.md).

---

## 1. Context

Credenza can present itself to DERIVA as a drop-in, **webauthn2-compatible** authentication
and session-broker service, so existing DERIVA consumers (ermrest, hatrac, Chaise, deriva-py,
the bdbag keychain, the webauthn2 client library) work with no client-side change. That
compatibility is gated by `ENABLE_LEGACY_API`, which is not one switch but a bundle of
behaviors across **four independent axes**. The goal of this ADR is to retire `ENABLE_LEGACY_API`
without forcing a coordinated flag-day across all of DERIVA, and while **keeping** the parts of
the "legacy" surface that are genuinely valuable.

### Axis 1 -- the session *object* (the contract DERIVA reads)
- `make_session_response` (`rest/session.py:282`) emits the webauthn2 `client` + `attributes`
  document instead of the modern shape.
- Identities flatten to a list of id strings (`session.py:303`) unless `LEGACY_IDENTITY_DETAIL`;
  `client.id` is the `iss/sub` composite (`session.py:290`).
- `PUT /session` refreshes upstream tokens when due, as if `refresh_upstream=true` were passed,
  but does not re-run augmentation.

The modern shape already exists (`session.py:314-362`): `preferred_username`, `full_name`,
`email`, `email_verified`, `sub`, `iss`, `aud`, `id`, `userid`, `groups`, `roles`,
`identities` (map keyed by canonical id), `scopes`, `resources`, `metadata`, ISO timestamps.

### Axis 2 -- the first-party cookie login flow (RETAINED -- not retired)
- Credenza-as-RP: `GET /login` -> IDP -> `GET /callback` sets a session cookie. This is a
  valued "canned" first-party browser login convenience. **Decision: keep it.** Chaise stays a
  cookie consumer and does **not** become an OAuth+PKCE SPA.
- What *is* removed here is only the webauthn2 *compatibility shim* `/preauth` (`login.py:375`)
  and the legacy response quirks: `/logout` returning `{logout_url}` JSON (`login.py:361`) and
  `DELETE /session` redirecting to `/logout` (`session.py:225`). Cookie name `webauthn` vs
  `credenza` (`app.py:116`) is transitional.

### Axis 3 -- resource-binding laxity
- Legacy seeds `LEGACY_DEFAULT_RESOURCE` (`urn:deriva:rest:service:all`) at device auth
  (`device.py:57`), introspection (`introspect.py:107`), and effective-scope resolution
  (`util.py:339`, with `# TODO: remove this, eventually` at `util.py:593`). This is the
  "everything is `service:all`" assumption that lets DERIVA never send a `resource` param.

### Axis 4 -- the OOB Globus "bring-your-own-bearer-token" session path
- `get_current_session` (`util.py:58-60`), only when `ENABLE_LEGACY_API` is set, lazily calls
  `session_from_bearer_token` when a presented bearer is not a known session key.
- `session_from_bearer_token` (`globus_provider.py:150`) validates a **Globus** access token,
  checks scope/issuer against the realm `accepted_scopes`, enriches, and creates a USER session
  that **uses the Globus token itself as the session key** (`use_access_token_as_session_key=True`).
- `/discovery` (`discovery.py:24`) feeds the client (`deriva-globus-auth-utils`) the accepted
  oauth2 scopes.

#### Axis 4 breaks the brokering property (a security reason to migrate ASAP)

In every other Credenza flow the bearer the client holds is an **opaque, Credenza-minted session
key** -- a random handle into the server-side session store. The upstream IDP tokens (access,
refresh, id) are sealed server-side (AES-GCM at rest) and never leave Credenza; downstream
resource servers authenticate by **introspecting Credenza, not the IDP**. This indirection is the
core brokering property (see security_model.md, "Session brokering", and credenza-flow.md).

The OOB Globus path inverts this. The client obtains a **Globus access token** out-of-band, presents
it, and Credenza creates the session with `use_access_token_as_session_key=True`
(`globus_provider.py:202`; `session_store.py:239` then sets `session_key = access_token`). So the
**session key *is* the Globus access token** -- the upstream token is the live downstream bearer,
flowing on every request to Credenza and DERIVA services, rather than being sealed server-side.

Consequences, and why this elevates Axis 4 from "cleanup" to "migrate ASAP":

1. **Cross-service blast radius.** The same token is a valid credential against **Globus's own APIs**
   (Auth, Transfer, Groups) *and* the DERIVA bearer. A leaked DERIVA bearer is therefore also a live
   Globus credential, replayable far beyond DERIVA. A stolen opaque Credenza key unlocks only that
   one Credenza session and is useless against Globus.
2. **No lifetime/revocation decoupling.** With brokering, Credenza rotates/refreshes the upstream
   token server-side while the downstream key stays stable, and can revoke the session independently.
   Here the downstream credential and the upstream token are the same object: session validity is
   pinned to the Globus token, and the key cannot be rotated without the user re-authenticating to
   Globus.
3. **Weaker audience binding.** The Globus token was minted with Globus's audience/scopes, not bound
   to DERIVA as a resource. The `accepted_scopes`/issuer check in `session_from_bearer_token`
   screens this after the fact, but it is not the resource-binding (RFC 8707 / 9728) the modern path
   provides.
4. **A secret doubling as a store key.** The high-value bearer is also the session-store lookup key
   (`get_active_session_by_session_key(bearer_token)`).

The replacement, `deriva-credenza-auth-utils` (device flow), returns an **opaque Credenza session
key** and keeps the Globus tokens server-side, **restoring** the brokering property. Phase 4's payoff
is therefore a concrete security improvement -- upstream tokens stop being client-held bearers -- not
merely surface reduction. This is an argument for prioritizing the `deriva-globus-auth-utils` ->
`deriva-credenza-auth-utils` client migration that gates Axis-4 retirement.

**The work of retiring `ENABLE_LEGACY_API` is primarily a DERIVA-stack change** (consumers must
read the modern session), alongside a prioritized, must-do retirement of Axis-4 (gated on replacing
its client tool) driven concurrently. Credenza already has the modern path.

---

## 2. Scope decisions (settled)

| # | Question | Decision |
|---|----------|----------|
| 1 | Flow vs shape | **Keep the first-party cookie login flow (Axis 2) as a supported feature. Modernize the session shape (Axis 1).** Chaise stays cookie-based; no OAuth+PKCE SPA. |
| 2 | Identity continuity | **Soft constraint.** Preserve existing ACL identity ids where feasible; re-key only where necessary. Decided per provider. |
| 3 | Resource tightening (Axis 3) | **Desired, deferrable.** Use the modernization as the reason to tighten, but allow it as a later, separately gated phase. |
| 4 | Consumer scope | **All DERIVA consumers.** |
| 5 | Endpoint cleanup | **Drop `/preauth`.** **Keep `/discovery` + `session_from_bearer_token` (Axis 4) until `deriva-globus-auth-utils` is retired** and clients move exclusively to `deriva-credenza-auth-utils` (device flow); then drop the Axis-4 path as a unit. |
| 6 | Axis-4 priority | **Must-do, not best-effort.** Axis 4 violates the session-brokering property (the Globus token *is* the client bearer -- see "Axis 4 breaks the brokering property"). The `deriva-globus-auth-utils` -> `deriva-credenza-auth-utils` client migration that gates Axis-4 retirement is **expedited and treated as required**, not allowed to slip indefinitely. |

---

## 3. Recommended approach: an additive (superset) `/session` document

Given "keep the flow + modernize the shape + all consumers must move," neither a flag-day swap
(too risky across every consumer at once) nor a second endpoint/flow (violates "keep the flow")
fits. The approach that does:

**Emit a single `/session` document that is a superset -- modern keys PLUS the legacy
`client`/`attributes` block -- during a transition window. Each consumer migrates from the
legacy keys to the modern keys independently. Once all consumers are migrated, the legacy keys
(and the Axis-1 branch) are removed.**

Properties:
- One endpoint, one cookie flow, one session record. Honors decisions #1 and #5.
- No flag day: consumers migrate field-by-field on their own schedule. Honors #4.
- `ENABLE_LEGACY_API` changes meaning from a *shape switch* to, at most, a *deprecation toggle*
  controlling whether the legacy `client`/`attributes` keys are still emitted, then is deleted.
- Soft identity continuity (#2) is handled inside the superset: modern keys carry the same id
  strings where we want continuity, and re-key explicitly where we choose to; the legacy block
  keeps old consumers working meanwhile.
- Resource tightening (#3) and Axis-4 retirement (#5) are orthogonal and sequenced separately.

### Alternatives considered
- **Flag-day in-place swap** -- rejected: unacceptable coordinated-release risk across DERIVA.
- **Versioned/negotiated endpoint** (`/session?v=2`, Accept header, `/session2`) -- rejected for
  now: adds a second contract to maintain; the superset gives independent migration with one
  endpoint.

---

## 4. Open analysis required before implementation

> **Status (2026-06-12): TABLED for a future session.** Sections 4.1 (per-consumer inventory) and
> 4.2 (per-provider identity-continuity matrix) are the gating analyses for Phase 1 and are not yet
> done. Completing them requires reading the consumer-side repos (ermrest, hatrac, the webauthn2
> client library, Chaise, deriva-py). Pick this up before any Phase 1 implementation.

### 4.1 Per-consumer inventory (TODO)
Record exactly which session fields each consumer reads, so we know the minimal modern surface
each must adopt and can sequence the migration.

| Consumer | Reads today | Used for | Modern target | Notes |
|----------|-------------|----------|---------------|-------|
| webauthn2 client lib | `client` / `attributes` | shared parsing for servers below | (TODO) | highest-leverage single change |
| ermrest (server) | `client.id`, `attributes[].id` | ACL match (identity + groups) | `id`, `groups`, `identities` | authoritative ACL decider |
| hatrac (server) | (TODO) | object ACLs | (TODO) | |
| Chaise (browser) | `client.display_name`, `client.identities` | UI identity display / login state | `preferred_username`, `identities` | UI only -- no flow change |
| deriva-py | `/authn/session` client block | CLI identity / keychain | (TODO) | `credenza_auth_utils.py` |
| bdbag keychain | bearer token only | resource fetch auth | n/a | not a session-shape consumer |

### 4.2 Per-provider identity-continuity matrix (TODO -- gates decision #2)
The ACL surface matches on id strings. The question is whether the modern keys carry the **same**
id strings as legacy `client.id` / `attributes[].id` / `client.identities[]`, per IDP.

| Provider | Legacy `client.id` | Modern `id` | Legacy identity ids | Modern `identities` keys | Group id form | Continuity / re-key |
|----------|--------------------|-------------|---------------------|--------------------------|---------------|---------------------|
| Globus | `iss/sub` | `iss/sub` | `<iss>/<sub>` (from `identity_set`) | `<iss>/<sub>` (`globus_provider.build_identities`) | (TODO) | likely continuous |
| NIH-RAS / login.gov | `iss/sub` | `iss/sub` | `identity_username` (e.g. `...@login.gov`) | keyed by `identity_username` | (TODO) | (TODO) |
| Keycloak | (TODO) | (TODO) | (TODO) | (TODO) | (TODO) | (TODO) |

Note: legacy `attributes` flattens client + groups + roles + resources + scopes + claims into one
`{id, display_name}` array (`session.py:307-308`); the modern shape splits these into typed arrays.
The migration must keep the ACL-relevant id strings unchanged where continuity is chosen.

---

## 5. Proposed phasing (draft)

1. **Phase 0 -- Inventory.** Complete 4.1 and 4.2. No code change. Gates everything.
2. **Phase 1 -- Superset emission.** `/session` emits modern keys alongside `client`/`attributes`
   regardless of `ENABLE_LEGACY_API`; redefine the flag to mean "still emit the legacy block."
   Pure additive; no consumer change.
3. **Phase 2 -- Consumer migration.** webauthn2 client lib first (highest leverage), then
   ermrest/hatrac, then Chaise and deriva-py, each reading modern keys.
4. **Phase 3 -- Legacy block + shim retirement.** Once all consumers are migrated: stop emitting
   the legacy block, delete the Axis-1 branch, and remove `/preauth` and the legacy `/logout` /
   `DELETE /session` quirks. Also remove the transitional `CREDENZA_LEGACY_DEVICE_REFRESH_ON_USE`
   setting, which lets legacy session-proxy `PUT`s refresh device sessions started without
   automatic refresh.
5. **Phase 4 (must-do, runs in parallel) -- Axis 4 retirement.** Treated as required, not best-effort,
   because of the brokering-property violation (decision #6). Expedite the `deriva-globus-auth-utils`
   -> `deriva-credenza-auth-utils` client migration; once clients have moved, remove `/discovery`,
   `session_from_bearer_token`, and the `get_current_session` bearer-token fallback. This track does
   not depend on Phases 1-3 and should be driven concurrently rather than queued behind them.
6. **Phase 5 (independently gated) -- Axis 3 tightening.** Remove `LEGACY_DEFAULT_RESOURCE`
   reliance; require declared resources per service. May slip independently.

---

## 6. Open questions

- **Target end state.** Section 7 collects strategies for what replaces the legacy session lookup,
  extension and authorization model; it is the working space for choosing among them.
- **`refresh_upstream` semantics.** Legacy makes every `PUT /session` refresh upstream tokens when
  they are due; augmentation re-runs only on an explicit `refresh_upstream=true`. Do modern
  consumers want always-live token semantics, or explicit opt-in? Affects upstream load/latency.
- **`LEGACY_IDENTITY_DETAIL`** -- does any consumer need the flat-list identity form, or can the
  modern `identities` map be the single representation from the start?
- **Cookie name.** Keep `webauthn` during transition (since we keep the flow), or decouple cookie
  name from the shape migration? Likely keep `webauthn` until Phase 3.
- **Group/role provenance.** Are DERIVA groups sourced from the IDP `groups` claim or a separate
  DERIVA groups service? Determines whether group-id continuity is a Credenza concern at all.
- **Deprecation window** length for the legacy block, and whether it is per-deployment.

---

## 7. Target end state after legacy mode (strategies under discussion)

This section is a working space for strategies, not decisions. It describes where the session
contract could end up once `ENABLE_LEGACY_API` and the webauthn2-era consumers are gone, so the
phasing above has a destination to aim at. Each strategy lists what it would remove, what it would
cost and what is still open. Nothing here is settled.

### 7.1 Why the current design is convoluted

Four properties of the legacy contract force most of the complexity in Credenza's session code
today:

1. **Session lookup is a write.** Resource servers (ERMrest, hatrac) identify a caller through the
   webauthn2 session proxy, which sends `PUT /authn/session`. That both returns the session and
   extends it, and in legacy mode also refreshes the upstream tokens of automatically refreshed
   device sessions when due. The most frequent
   request Credenza serves is therefore a read-modify-write on the session record. That is why
   device-session `PUT`s need a per-session lock, a 2-second wait cap and a no-write fallback.
2. **Authorization data lives in the resource server that needs it.** Role and access-grant
   principals are computed by querying ERMrest with the user's own session key, while ERMrest may
   itself be in the middle of asking Credenza who the user is. On a cache miss ERMrest's proxy
   sends `PUT /authn/session` for the same session, so re-running augmentation on every lookup
   would recurse. Today that is avoided by re-running augmentation only on an explicit
   `refresh_upstream=true` or after a worker token refresh, and always outside the session lock.
3. **Authorization is a snapshot frozen into the session.** Principals are copied into the session
   at login and on refresh, so revoking a grant takes effect only when the snapshot is recomputed:
   about 30 minutes for automatically refreshed device sessions, and not until the session ends
   for browser sessions (up to 24 hours, or the realm's `session_max_lifetime.user`).
4. **The legacy document shape is the contract.** The `client` / `attributes` block, the flattened
   identities list and the `webauthn` cookie name all exist for compatibility.

### 7.2 Strategies

#### A. Read-only lookup for resource servers

Resource servers stop extending sessions as a side effect of identifying the caller.

- **A1. RFC 7662 introspection.** ERMrest and hatrac register as Credenza clients and call
  `POST /introspect`, caching the answer briefly. Introspection never extends a session, refreshes
  tokens or re-runs augmentation, so the frequent path is a pure read: no writes, no locks, no
  calls to ERMrest or the IdP. The response already carries Credenza's identity model, including
  `roles` and `groups`. Adding a `sid` claim (the OIDC name for a session id, not a credential)
  would give resource servers the log-correlation key directly, replacing the `tracking` field.
  - Cost: each resource server needs client credentials, and its session client library changes
    from parsing `/session` to parsing introspection. It also departs from section 3's
    single-`/session` approach, so the two would need reconciling.
- **A2. Read-only `GET /session`.** Keep `/session` as the lookup (consistent with section 3), but
  the modern session client library sends `GET`, which never writes. Extension then has to happen
  elsewhere (strategy B).
  - Cost: a smaller consumer change than A1, but `/session` keeps serving two audiences, browsers
    and resource servers, with different needs.
- Open: whether the resource-server cache TTL (60 s today) is acceptable as the effective
  revocation delay once the hot path no longer writes.

#### B. Explicit session extension

If lookups stop extending sessions, something else must.

- **Browser sessions:** Chaise extends its own session from user activity, rate-limited (the
  cookie login flow is kept, per decision #1).
- **Device sessions:** already do not slide. A session with automatic refresh expires at its
  absolute lifetime and the worker keeps its tokens alive; one without ends with its upstream
  access token unless the client sends `refresh_upstream=true`. Nothing needs to extend them on
  use, apart from the transitional `CREDENZA_LEGACY_DEVICE_REFRESH_ON_USE` setting.
- Effect: with A and B together, the per-session lock is needed only around refresh and delete,
  both of which are infrequent.
- Open: whether any consumer relies on a session staying alive purely because a resource server
  keeps looking it up (for example long-running server-side jobs holding a user's token).

#### C. Authorization data from a source that does not depend on Credenza

- **C1. Credenza computes principals with its own credential.** Augmentation queries the role and
  access-grant tables using a Credenza service identity with a narrow, read-only grant, instead of
  the user's session key. Recursion becomes impossible by construction, and augmentation no longer
  needs a live user session.
  - Cost: a new trust edge. Credenza reads authorization tables directly, and the scope of that
    grant has to be defined and reviewed per deployment.
- **C2. Push instead of poll.** A change to a role binding or access grant triggers recomputing or
  invalidating the affected sessions: an event from ERMrest, or a periodic diff of the source
  tables. Revocation then reaches open sessions within seconds, not on the next refresh.
  - Cost: needs a change feed or diffing mechanism, and a way to map a changed grant to the
    sessions it affects.
- C1 and C2 combine: C1 removes the recursion, C2 removes the revocation delay.
- Open: C1 or C2 first; and whether C2 should target only revocations (the security-relevant
  direction) while grants keep arriving on the normal refresh cycle.

#### D. Evaluate some authorization inside the resource server

ERMrest's dynamic ACL bindings can decide membership at request time by joining the client id to
role or access-grant tables, so a grant change applies on the next request with no session
principal at all.

- Limits: hatrac ACLs are static principal lists, so file access would still need principals
  carried in the session. D can complement C but not replace it.
- Cost: moves policy into catalog ACL configuration, and makes each request's authorization
  depend on query cost.
- Open: how far dynamic bindings can express the access rules deployments actually use.

#### E. One session document

The modern document only: the `identities` map rather than the flattened list, linked identities
never treated as ACL principals, the cookie name decoupled from `webauthn`, and no
`refresh_upstream` overloading of the lookup.

- This is the end point of the phasing in section 5; it is listed here so the other strategies can
  assume it.

#### F. Scaling beyond one process

The session locks are in-process and assume a single Credenza process. With A and B the frequent
path no longer takes them, so only refresh and delete would need a store-provided lease (for
example `SET NX` on Redis/Valkey or an advisory lock on PostgreSQL) to run several processes or
hosts against a shared store.

- Open: whether horizontal scaling is a real requirement; today it is not expected.

### 7.3 What the end state would remove

- the legacy forced upstream refresh on every `PUT /session`;
- the lock, 2-second cap and no-write fallback on the frequent lookup path;
- the out-of-lock re-augmentation (`reaugment_session`) and the recursion risk it guards against;
- the `tracking` field as a log-correlation workaround;
- most of the revocation delay for open sessions.

### 7.4 Open questions for this section

- A1 or A2 for resource-server lookup, and how either fits section 3's single-`/session` approach.
- Whether a Credenza service identity reading authorization tables (C1) is acceptable in
  principle, or the end state should lean on push from the catalog (C2).
- Which of these can ride on the phasing in section 5 and which need their own phases.
