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
- `GET /session` forces `refresh_upstream=True` (`session.py:60`).

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
   `DELETE /session` quirks.
5. **Phase 4 (must-do, runs in parallel) -- Axis 4 retirement.** Treated as required, not best-effort,
   because of the brokering-property violation (decision #6). Expedite the `deriva-globus-auth-utils`
   -> `deriva-credenza-auth-utils` client migration; once clients have moved, remove `/discovery`,
   `session_from_bearer_token`, and the `get_current_session` bearer-token fallback. This track does
   not depend on Phases 1-3 and should be driven concurrently rather than queued behind them.
6. **Phase 5 (independently gated) -- Axis 3 tightening.** Remove `LEGACY_DEFAULT_RESOURCE`
   reliance; require declared resources per service. May slip independently.

---

## 6. Open questions

- **`refresh_upstream` semantics.** Legacy forces `refresh_upstream=True` on every `/session`
  (`session.py:60`). Do modern consumers want always-live semantics, or explicit opt-in? Affects
  upstream load/latency.
- **`LEGACY_IDENTITY_DETAIL`** -- does any consumer need the flat-list identity form, or can the
  modern `identities` map be the single representation from the start?
- **Cookie name.** Keep `webauthn` during transition (since we keep the flow), or decouple cookie
  name from the shape migration? Likely keep `webauthn` until Phase 3.
- **Group/role provenance.** Are DERIVA groups sourced from the IDP `groups` claim or a separate
  DERIVA groups service? Determines whether group-id continuity is a Credenza concern at all.
- **Deprecation window** length for the legacy block, and whether it is per-deployment.