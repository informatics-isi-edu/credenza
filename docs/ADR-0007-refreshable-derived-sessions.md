# ADR-0007: Refreshable Derived Sessions for IDPs Without offline_access

## 1. Status

**Proposed**
Decision Date: 2026-05-19

### Review History

| Date       | Status   | Notes                                                    |
|------------|----------|----------------------------------------------------------|
| 2026-05-19 | Proposed | Initial draft                                            |

---

## 2. Context

### 2.1 The Gap

Long-running, non-interactive API workloads against Credenza-protected
resource servers (the canonical example being batch ETL into DERIVA via
deriva-mcp-core or `deriva-py`) currently depend on the device flow with
upstream `offline_access`. The device flow obtains an upstream refresh token
from the IDP and uses it, via the background refresh worker, to keep the
device-typed Credenza session alive across long runs without re-prompting the
user.

NIH's Research Authorization Service (RAS) -- to be integrated per ADR-0005
-- and the federated IDPs to which it delegates (login.gov, ID.me) **do not
support `offline_access` and do not issue refresh tokens**. NIH's published
guidance for long-running API access against RAS-protected resources is to
use scope- and resource-limited Token Exchange (RFC 8693) instead of upstream
offline access.

With Credenza's current design that path tops out at a globally configured
`DERIVED_SESSION_MAX_TTL` of 1800 seconds and forces the client to re-prompt
the user for a fresh interactive login (or device-flow approval) before the
upstream session expires. For a multi-hour batch operation this is
operationally unworkable.

### 2.2 Current Design and Its Assumption

`_handle_token_exchange_grant()` in `rest/token.py` issues a DERIVED session
whose lifetime is

```
ttl = min(DERIVED_SESSION_MAX_TTL, client.max_session_ttl_seconds)
```

and creates the session row with `absolute_session_lifetime_secs = ttl`,
i.e., the per-issuance TTL and the absolute cap are the same value. DERIVED
sessions are explicitly non-extendable and the RFC 8693 response carries no
`refresh_token` field. This is consistent with the original ADR-0001 Phase
4.3 commitment ("Short-lived. Non-refreshable. Non-extendable.").

The implicit assumption was that any client needing durability beyond a
single derived-session window would obtain it through the device flow with
upstream `offline_access`. That assumption is no longer universally true
once RAS and its federated IDPs come into scope.

### 2.3 Why Not Per-Target TTL

A natural alternative -- extending `allowed_token_exchange_targets` from a
flat `List[str]` into a per-target structure carrying per-target TTL
overrides -- would let admins say "DERIVA REST = 1h, hatrac upload = 5
min". This is rejected (see Section 4.1). Briefly: per-target TTL bakes
operational policy into the static client registry, makes the cap visible
in token lifetimes alone (no rotation), and does not address the fundamental
need, which is durability *across* a long-running job, not differentiated
exposure windows *within* it. A standard refresh-token model addresses
durability directly and remains compatible with introducing per-target TTL
later if a concrete use case ever justifies it.

### 2.4 Relationship to ADR-0001

This ADR deliberately revises the ADR-0001 Phase 4.3 stance from
"non-refreshable" to "refreshable, opt-in, and capped by an immutable
wall-clock absolute lifetime stamped at the moment of the initial exchange".
"Non-extendable" is retained in the sense that the absolute cap is set once
at initial exchange and is never modified by any subsequent refresh; only
the access-token secret and the refresh-token secret rotate.

---

## 3. Decision

Credenza SHALL support optional, opt-in refresh tokens for DERIVED sessions.
The capability is gated per client and bounded by a three-tier configuration
that lets realm-level operators (notably the RAS realm) impose tighter caps
than other deployments.

### 3.1 TTL Tier Structure

Two distinct quantities are computed at the moment of the initial token
exchange:

**Per-issuance access-token TTL** -- a *fallback chain*, not a ceiling. The
first non-`None` value in the following sequence wins:

```
ttl = (
    client.max_derived_session_ttl_seconds                # new optional client field, takes precedence
    or client.max_session_ttl_seconds                     # backward-compat fallback
    or config.DERIVED_SESSION_DEFAULT_MAX_TTL             # global default, used only when nothing is configured (default 1800s)
)
```

The introduction of `max_derived_session_ttl_seconds` lets administrators
configure a client whose interactive (USER) sessions are short-lived but
whose derived (DERIVED) access tokens are longer-lived (or vice versa)
without overloading the existing field. Existing deployments that set only
`max_session_ttl_seconds` retain their current behavior.

The existing global constant `DERIVED_SESSION_MAX_TTL` (and its environment
variable `CREDENZA_DERIVED_SESSION_MAX_TTL`) are **renamed** to
`DERIVED_SESSION_DEFAULT_MAX_TTL` / `CREDENZA_DERIVED_SESSION_DEFAULT_MAX_TTL`
as part of this ADR. The old name implied a ceiling; the new name
correctly conveys that the value is a *default* applied only when no
client-level configuration is present. A client that configures
`max_derived_session_ttl_seconds = 7200` will receive 7200-second access
tokens regardless of the global value. This is a deliberate departure
from the current behavior of `_handle_token_exchange_grant()`, which
clamps `client.max_session_ttl_seconds` to `min(global, client)`.
Rationale: the per-issuance TTL is an operational tuning knob ("how
often must my client refresh?") and not the security boundary. The
security boundary is the absolute cap (below), which is layered with
`min()` precisely so that realm- and global-level operators can override
permissive client configuration. Conflating "global default TTL" with
"global ceiling on TTL" caused the original confusion and is removed
here.

The legacy environment variable name is silently dropped; Credenza is
minimally deployed at this time and the cost of a backward-compat alias
is not justified.

In all cases the effective issuance is implicitly bounded by the absolute
cap via the issuance-time clamp `expires_at = min(now + ttl, absolute_expires_at)`,
so even a very large per-issuance TTL cannot extend the chain beyond the
wall-clock policy.

**Absolute wall-clock cap** (stamped once, immutable thereafter):

```
absolute_lifetime = min(
    config.DERIVED_SESSION_ABSOLUTE_LIFETIME_MAX,                       # global, default 86400s
    realm.derived_session_absolute_lifetime_seconds,                    # per-realm cap in IDP profile
    client.derived_session_absolute_lifetime_seconds or realm_value,    # optional client override
)
```

The realm tier lives in `OIDC_IDP_PROFILES[realm]["derived_session_absolute_lifetime_seconds"]`
and follows the three-layer config merge pattern already established for
`consent_labels` in ADR-0002. The RAS realm can be locked to a tight value
(e.g. 4 hours) while a Keycloak-backed deployment may permit longer.

The absolute cap is stamped onto the DERIVED session row as
`absolute_expires_at = now + absolute_lifetime` at the moment of initial
exchange. **No refresh operation may modify this value.** The existing
`enforce_absolute_cap()` check (in `api/session/storage/session_store.py`)
already runs on every session read and provides the enforcement mechanism
without additional code.

### 3.2 Refresh Token Eligibility and Authentication

Refresh-token issuance is gated by a new per-client flag
`derived_refresh_token_enabled` (default `false`). Clients must additionally
include `refresh_token` in `allowed_grant_types` to redeem tokens at
`/token`.

Both confidential and public clients are eligible when the flag is enabled.
This is necessary because the RAS use case is structurally
`device_flow (public client) -> token_exchange -> refresh`, where the
originating client is public; restricting refresh to confidential clients
would block the very flow this ADR exists to enable. OAuth 2.1 BCP §4.14
explicitly permits refresh tokens for public clients provided rotation with
reuse detection is in place (which this ADR mandates).

Client authentication on `/token` for the `refresh_token` grant follows
the same posture as `token_exchange`:

- **Confidential clients** invoke `adapter_authenticate()` on every refresh
  call, identical to the existing token_exchange path.
- **Public clients** present `client_id` in the request body; the
  refresh-token storage record carries the originally bound `client_id`
  and a mismatch is rejected. Security relies on refresh-token secrecy +
  rotation + reuse detection.

### 3.3 Single-Use Rotation with Reuse Detection

Refresh tokens are single-use. Each `/token` call with
`grant_type=refresh_token` atomically consumes the presented refresh-token
record via the existing `backend.consume()` primitive (the same primitive
used today for authorization codes: Redis `GETDEL`, PostgreSQL
`DELETE ... RETURNING`). A successful consume yields a new access token
**and** a new refresh token; the old refresh token is immediately invalid.

If `consume()` returns `None` -- i.e., the presented refresh token does not
exist in storage -- Credenza emits a `refresh_token_reuse_detected_or_invalid`
audit event and returns `invalid_grant`. A future iteration may add a
secondary index allowing the server to map the presented token back to its
chain and proactively delete the underlying DERIVED session (true OAuth 2.1
reuse-detection semantics); the initial implementation conservatively rejects
without such a lookup, since the consumed-token state alone is sufficient
to deny the leaked token any further utility.

Refresh-token storage entries are keyed by `sha256(refresh_token)` and live
under `credenza:oidc:derived_refresh:<hash>`, mirroring the hashing
convention introduced for pending-consent storage in ADR-0002. The stored
record contains `{client_id, session_id, absolute_expires_at, issued_at}`
and its backend TTL is set to `absolute_expires_at - now` so that storage
cannot outlive the absolute cap even if application code mishandles the
expiry check.

### 3.4 Session Identity on Refresh

A refresh operation **reuses the existing DERIVED `session_id`**. Only the
access token (the `skey` mapping) and the refresh token rotate. The
`absolute_expires_at` on the session row is set once at initial exchange
and is never touched again.

Concretely, on a successful refresh:

1. The old `skey -> sid` mapping is invalidated.
2. A new `skey` is generated, the new `skey -> sid` mapping installed, and
   the `sid -> skey` mapping updated.
3. `session.expires_at` is bumped to `min(now + ttl, absolute_expires_at)`.
4. A new refresh-token record is written for the same `sid`.

The mint-new alternative (each refresh creates a new DERIVED session and
deletes the old) was rejected (Section 4.3). The deciding factor is that
the absolute cap is the single most security-critical invariant introduced
by this ADR; with reuse-on-refresh, the cap lives on one row and is
enforced by code that already runs, whereas mint-new would require every
refresh handler edit to remember to copy `absolute_expires_at` forward --
exactly the kind of footgun that breaks silently months later. Audit-trail
continuity (a stable `session_id` linkable to the original
`base_session_id` recorded at initial exchange) is a strong secondary
reason.

### 3.5 New `/token` Grant: `refresh_token`

A new handler `_handle_refresh_token_grant(proof_ctx, client_rec, store)`
is added alongside the existing grant handlers. RFC 8414 discovery
(`rest/metadata.py`) advertises `refresh_token` in `grant_types_supported`.

The handler:

1. Extracts `refresh_token` and `client_id` from the request body; 400 on
   missing.
2. For confidential clients, invokes `adapter_authenticate()`.
3. Atomically consumes the refresh-token record. `None` -> reuse detection
   audit + `invalid_grant`.
4. Validates the stored `client_id` matches the presented one.
5. Loads the DERIVED session by `sid`. Missing, wrong type, or
   `now >= absolute_expires_at` -> `invalid_grant`.
6. Computes the new per-issuance TTL (clamped so `now + ttl <=
   absolute_expires_at`) and rotates `skey` on the existing session row.
7. Writes a new refresh-token record bound to the same `sid` and the same
   immutable `absolute_expires_at`.
8. Emits `refresh_token_issued` audit event.
9. Returns `{access_token, refresh_token, token_type, expires_in, scope}`.

---

## 4. Alternatives Considered

### 4.1 Per-Target TTL on `allowed_token_exchange_targets`

Convert `allowed_token_exchange_targets` from `List[str]` to a per-target
dict carrying optional `max_ttl_seconds` per target, with no refresh-token
capability.

**Rejected.** Does not address durability across a multi-hour job (the
actual RAS-driven requirement), only differentiated exposure windows within
a single issuance. A long-lived per-target access token has a strictly
larger exposure window than a short access token + rotated refresh token of
equivalent total duration, because a leaked long-lived access token is
usable without any client-binding check, whereas a leaked refresh token
must be presented with the original `client_id` and is consumed on first
use. Per-target TTL also bakes operational policy into static client
registry config and forfeits the audit/revocation benefits that
single-use rotation provides. Not foreclosed -- it can be added later if a
concrete use case justifies it -- but not the right primary path for the
stated problem.

### 4.2 Re-usable Refresh Tokens

Issue a refresh token that may be presented repeatedly until
`absolute_expires_at` rather than rotating on each use.

**Rejected.** Loses theft detection: a leaked refresh token is usable for
the full wall-clock window. Inconsistent with OAuth 2.1 BCP §4.14, which
requires either sender-constrained tokens (DPoP/mTLS, not currently in
Credenza) or rotation with reuse detection for public-client refresh.
Since this ADR extends refresh-token issuance to public clients, the
rotation path is mandatory.

### 4.3 Mint New DERIVED Session per Refresh

Each refresh creates a new DERIVED session (copying scopes, resources, and
`absolute_expires_at` from the predecessor) and deletes the old one.

**Rejected.** The absolute cap survives only as long as every refresh
handler edit remembers to copy the field forward; a missing copy silently
extends the chain past its cap. Revocation requires tracking "the current
sid in the chain" externally. RS-side introspection caches keyed by `sid`
are invalidated each rotation. The buyback (per-issuance audit row
isolation) is achievable equivalently with explicit `refresh_token_issued`
audit events.

### 4.4 Restrict Refresh to Confidential Clients

Issue refresh tokens only when the client is confidential, on the
reasoning that public clients cannot prove possession of a static secret.

**Rejected.** Blocks the RAS use case (device flow -> token exchange ->
refresh, where the originating client is public) and conflates two
distinct security properties. The OAuth 2.1-approved guard for
public-client refresh is rotation with reuse detection (this ADR §3.3) plus
client-ID binding on the stored record. Credenza's existing device-flow
posture already stores upstream refresh tokens on public-client sessions
and trusts that storage; extending the same posture to derived sessions
crosses no new trust boundary.

### 4.5 Status Quo Plus Longer Subject (USER) Session

Leave the derived-session model untouched and instead encourage operators
to set `client.absolute_session_lifetime_seconds` to many hours on the
client used for the initial interactive login, then have the API client
re-exchange every ~25 minutes for the duration of the job.

**Rejected.** Technically functional but operationally fragile: every API
client must implement an exchange loop with no help from existing OAuth
client libraries, the 30-minute hard cap leaks into all client-side
scheduling, and no rotation/reuse detection is provided on the derived
access token. Also concentrates risk on the long-lived USER session
secret, which is a primary credential (revoking it kills the user's
browser session too), rather than on a purpose-built refresh credential
scoped to a single delegation.

---

## 5. Security Considerations

### 5.1 OAuth 2.1 BCP §4.14 Compliance for Public Clients

Issuing refresh tokens to public clients is permitted by OAuth 2.1 BCP
§4.14 under one of two conditions: sender-constrained tokens (DPoP, mTLS)
or rotation with automatic reuse detection. Credenza implements the second
condition: every refresh atomically consumes the prior refresh token,
issues a replacement, and rejects any presentation of a token that is no
longer in storage. Combined with client-ID binding on the stored record,
this satisfies the BCP requirement for public clients without requiring
the DPoP/mTLS infrastructure that Credenza does not currently support.

### 5.2 Decoupling from Upstream Session

A DERIVED session is already decoupled from the upstream IDP session the
moment it is issued: no parent-session reference is stored, and the DERIVED
row's lifetime is governed entirely by Credenza. Extending that decoupling
through refresh tokens does not cross a new trust boundary, but it does
make the duration of the decoupling visible at the policy layer. The
`derived_session_absolute_lifetime_seconds` realm-level cap is the policy
control: for the RAS realm, where upstream sessions are typically short
and offline access is forbidden, operators should configure a value
consistent with NIH's "no decoupled access past N hours" expectations.

### 5.3 Absolute Wall-Clock Cap as the Critical Invariant

The absolute cap is the single most security-sensitive value introduced by
this ADR. It is stamped onto the DERIVED session row at initial exchange
and is never written again. The existing `enforce_absolute_cap()` check in
the session store is the enforcement mechanism. Any future code change
that touches the refresh path MUST NOT modify `absolute_expires_at`;
violating this invariant defeats the entire policy model.

### 5.4 Refresh Token Storage and Hashing

Refresh tokens at rest are stored under `sha256(refresh_token)` so that a
leaked storage dump does not directly yield usable bearer credentials. The
TTL of the storage entry is bounded by `absolute_expires_at - now` so that
storage cannot outlive the absolute cap even in the presence of an
application-level bug that fails to check expiry.

### 5.5 Revocation

Revocation of an entire refresh chain reduces to deleting the DERIVED
session row: the next refresh attempt will succeed at consuming the
refresh-token record but then fail to load the session, returning
`invalid_grant`. RFC 7009 `/revoke` SHALL be extended to accept derived
refresh tokens as well, hashing the presented token and removing both the
refresh-token storage entry and the underlying DERIVED session.

### 5.6 Audit Events

The following audit events are added or retained:

| Event                                     | When emitted                                                                                |
|-------------------------------------------|---------------------------------------------------------------------------------------------|
| `token_exchange_issued` (existing)        | Unchanged; logs `base_session_id` -> new DERIVED sid                                        |
| `refresh_token_issued`                    | Each successful refresh                                                                     |
| `refresh_token_reuse_detected_or_invalid` | Presented refresh token not in storage                                                      |
| `refresh_token_client_mismatch`           | Presented `client_id` differs from bound `client_id`                                        |
| `refresh_token_expired`                   | Presented within `absolute_expires_at` window but session row is gone or session_type wrong |

Each event carries `request_id` and `client_id`; the issued/expired events
also carry `session_id`, enabling chain-wide queries against a stable sid.

---

## 6. Implementation Sketch

Affected files (approximate):

- `credenza/rest/token.py` -- rename the module constant
  `DERIVED_SESSION_MAX_TTL` to `DERIVED_SESSION_DEFAULT_MAX_TTL`; modify
  `_handle_token_exchange_grant()` to compute and persist the absolute
  cap separately from the per-issuance TTL using the fallback-chain
  semantics from Section 3.1; conditionally issue a refresh token; add
  new `_handle_refresh_token_grant()`; update `/token` dispatch.
- `credenza/api/auth/client/client_registry.py` -- add three fields to
  `ClientRecord`: `max_derived_session_ttl_seconds: Optional[int] = None`,
  `derived_session_absolute_lifetime_seconds: Optional[int] = None`,
  `derived_refresh_token_enabled: bool = False`. Add `__post_init__`
  validation tying `derived_refresh_token_enabled=True` to the presence of
  `"refresh_token"` in `allowed_grant_types`.
- `credenza/api/session/storage/session_store.py` -- add
  `set_derived_refresh_token(...) -> str` and
  `consume_derived_refresh_token(...) -> Optional[dict]`, hashing keys per
  Section 5.4.
- `credenza/app.py` -- rename the env binding
  `CREDENZA_DERIVED_SESSION_MAX_TTL` ->
  `CREDENZA_DERIVED_SESSION_DEFAULT_MAX_TTL` (keyed into
  `app.config["DERIVED_SESSION_DEFAULT_MAX_TTL"]`); load the new
  `CREDENZA_DERIVED_SESSION_ABSOLUTE_LIFETIME_MAX` (default 86400) into
  `app.config["DERIVED_SESSION_ABSOLUTE_LIFETIME_MAX"]`. The legacy
  `CREDENZA_DERIVED_SESSION_MAX_TTL` env var is silently ignored.
- `credenza/rest/metadata.py` -- add `"refresh_token"` to
  `grant_types_supported` in the RFC 8414 discovery document.
- `credenza/rest/token.py` -- extend `revoke_token()` (RFC 7009) to accept
  derived refresh tokens.
- `config/client_registry_sample.json` -- add a worked example of a
  refresh-enabled public client representing the RAS batch-ETL pattern.
- `config/oidc_idp_profiles.sample.json` -- add
  `derived_session_absolute_lifetime_seconds` under the RAS realm block as
  the canonical example.
- `docs/ADR-0001-narrow-oauth-profile.md` -- short addendum noting that
  Phase 4.3 is superseded by this ADR with respect to the
  "non-refreshable" property.

New tests required (`test/rest/test_token.py`, `test/auth/test_client_registry.py`):

- Refresh issued only when `derived_refresh_token_enabled=True`.
- Refresh denied for clients without `refresh_token` in `allowed_grant_types`.
- Access-token TTL respects the fallback chain
  `max_derived_session_ttl_seconds -> max_session_ttl_seconds -> global default`;
  a client whose configured TTL exceeds `config.DERIVED_SESSION_DEFAULT_MAX_TTL`
  receives its configured value, not the global value.
- The issuance-time clamp `expires_at = min(now + ttl, absolute_expires_at)`
  ensures access tokens never outlive the absolute cap even when the
  per-issuance TTL is configured larger than the absolute window.
- Absolute cap = `min(global, realm, client)`; realm-only, client-only, and
  three-tier cases.
- Absolute cap is set once at initial exchange and not modified by any
  refresh (assert directly on the session row after multiple refreshes).
- Confidential client refresh succeeds with valid client_secret, fails
  without.
- Public client refresh succeeds with matching `client_id`, fails on
  mismatch.
- Single-use rotation: first refresh succeeds, replay of consumed token
  returns `invalid_grant` and emits the reuse audit event.
- Refresh after `absolute_expires_at` returns `invalid_grant`.
- Revocation: `delete(sid)` causes next refresh to return `invalid_grant`.
- DERIVED `session_id` is stable across the refresh chain (introspection
  returns same sid).
- Existing token_exchange tests continue to pass for clients that do not
  opt into refresh, with one expected revision:
  `test_token_exchange_ttl_capped` (which asserts that
  `client.max_session_ttl_seconds=9999` is clamped to the global value)
  must be rewritten to reflect the new
  fallback-not-ceiling semantics. The replacement should assert instead
  that a high configured TTL is honored *up to the absolute cap*, i.e.,
  that the absolute cap -- not the global default -- is the security
  boundary.

### Out of Scope (Possible Follow-ups)

- True OAuth 2.1 reuse-detection chain invalidation (a secondary index from
  refresh-token hash to chain id, enabling a leaked-and-rotated token to
  trigger immediate deletion of the underlying DERIVED session). Section
  3.3 records the conservative initial behavior; an index-backed
  implementation can be added without changing the wire protocol.
- Per-target TTL on `allowed_token_exchange_targets`. Foreclosed by this
  ADR only in the sense that it is not needed; a future ADR may add it if
  a concrete use case emerges.
- DPoP or mTLS sender-constrained refresh tokens (ADR-0003 covers mTLS
  client auth but not token binding). If introduced, public-client refresh
  could optionally require sender constraint as a stronger alternative to
  the rotation-only guard.