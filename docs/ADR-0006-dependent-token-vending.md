# ADR-0006: Dependent Token Vending via Token Exchange

## 1. Status

**Proposed**
Decision Date: 2026-04-30

### Review History

| Date       | Status   | Notes                                                              |
|------------|----------|--------------------------------------------------------------------|
| 2026-04-30 | Proposed | Initial draft                                                      |

---

## 2. Context

### 2.1 The Gap

When Credenza authenticates a user against an upstream IDP, the IDP may return
one or more auxiliary tokens alongside the primary access and ID tokens. Globus
is the canonical example: its dependent token grant causes Globus to return
separate access tokens for each upstream resource server that was included in
the original scope request (e.g., Globus Groups API, FAIR Research Identifiers). 
These tokens are stored in the session's `additional_tokens` structure, keyed by
scope URN, alongside a `resource_server` field identifying which upstream service 
each token targets.

At present there is no network-accessible path for an authorized client to
retrieve these tokens. The session augmentation infrastructure uses them
internally at session-creation time (e.g., to fetch and embed Globus group
memberships into `userinfo`), but that is server-side delegation -- the tokens
never leave the Credenza process.

### 2.2 Historical Context

The predecessor "webauthn" codebase introduced a "wallet" concept for this
purpose, but restricted wallet access to in-process server code acting in a
delegation capacity. That restriction was motivated by legitimate security
concerns about over-broad token disclosure. It is not a sustainable architecture
for a distributed system where clients -- such as an MCP server or a
science-domain plugin -- need to call upstream resource servers directly on
behalf of an authenticated user.

### 2.3 Generic Applicability

While Globus makes the problem concrete, the pattern is general. Any IDP or
OAuth AS that issues auxiliary tokens in the authentication response -- now or in
the future -- creates the same gap. The solution should not be Globus-specific.
The `additional_tokens` storage layer already handles arbitrary providers via
`process_additional_tokens` in the base augmentation provider; the vending
mechanism should be equally generic.

### 2.4 Relationship to Token Exchange

RFC 8693 defines token exchange as the standard mechanism by which a client
presents a subject token and receives a token scoped to a different resource or
audience. Credenza already implements this for Credenza-native resources: a
client exchanges a user's session key for a short-lived DERIVED session bound to
a specific resource. Dependent token vending is the same operation at a
different layer -- the target resource is not a Credenza-native resource server
but an upstream one whose token Credenza holds in escrow on the user's behalf.

---

## 3. Decision

Extend the existing `token_exchange` grant at `POST /token` to support dependent
token vending. When the requested `resource` maps to a stored upstream token in
the subject session's `additional_tokens`, Credenza returns that upstream token
(refreshed if expired) rather than minting a new DERIVED Credenza session. The
existing DERIVED session path is unchanged for Credenza-native resources.

### 3.1 Dispatch Logic

On receiving a token exchange request:

1. Validate the subject token and retrieve the subject session (unchanged).
2. Apply the existing authorization checks: client authentication, transitive
   exchange denial, `allowed_token_exchange_targets`, scope no-escalation
   (unchanged).
3. For each requested resource, attempt to locate a matching entry in
   `session.additional_tokens` by comparing the requested resource URI against
   the `resource_server` field of each stored token entry.
4. **If all requested resources match stored upstream tokens**: vend the upstream
   tokens (see Section 3.2). This is the new path.
5. **If no requested resources match stored upstream tokens**: apply the existing
   DERIVED session logic. This path is unchanged.
6. **If requested resources are a mix**: return an error. Mixing upstream and
   Credenza-native resources in a single exchange is not supported; the client
   must make separate requests.

### 3.2 Upstream Token Vending

When vending an upstream token:

- **Freshness**: check `expires_at` for each token to be returned. If the token
  is expired or within a configurable threshold (default: 60 seconds), attempt a
  refresh using the stored `refresh_token` for that scope. If no refresh token
  exists (the original was issued for online access only) and the token is
  expired, return `invalid_token`.
- **Response format**: return the upstream access token directly in the standard
  RFC 8693 response body:

  ```json
  {
    "access_token":      "<upstream-token>",
    "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
    "token_type":        "bearer",
    "expires_in":        <remaining-seconds>
  }
  ```

  The token type reflects the upstream token, not a Credenza session key.
- **Scope**: the scope of the returned token is whatever the upstream IDP issued
  for that resource server. Credenza does not re-filter it; the upstream AS is
  authoritative for the token's scope.
- **No DERIVED session is created** in this path. The upstream token is not a
  Credenza credential and must not be introspectable via Credenza's `/introspect`
  endpoint.

### 3.3 Authorization Controls

All existing token exchange authorization controls apply without modification:

- Confidential clients must authenticate via their adapter before any token is
  returned.
- The target resource must appear in the client's `allowed_token_exchange_targets`
  list. The same default-deny policy applies regardless of whether the target is
  a Credenza-native or upstream resource.
- The subject session must be active and non-derived.
- Rate limiting applies as for standard token exchange.

One additional per-client flag is introduced:

- `allow_upstream_token_vending: bool` (default: `false`): must be explicitly
  set to `true` in the client registry entry to enable the upstream vending path.
  This provides an additional coarse gate, ensuring that clients which only need
  DERIVED Credenza sessions cannot inadvertently (or maliciously) retrieve raw
  upstream tokens even if they have a matching `allowed_token_exchange_targets`
  entry.

### 3.4 Resource URI Lookup Index

`additional_tokens` is currently keyed by scope URN, with `resource_server`
stored as a field within each entry. An inverted index mapping resource URI to
scope key is needed for O(1) lookup at vend time. This index can be built lazily
when the session is first loaded, or maintained as a parallel structure in the
session augmentation output. The `base_provider.process_additional_tokens`
implementation should be updated to emit both the existing scope-keyed structure
and a `resource_server_index: dict[str, str]` (resource URI -> scope key) to
avoid repeated linear scans at vend time.

---

## 4. Alternatives Considered

### 4.1 Proxy Mode

Credenza proxies all upstream resource server calls on behalf of the client.
The client never receives an upstream token; it sends requests to Credenza which
forwards them.

**Rejected**: Not sustainable. Credenza is an auth broker, not an API gateway.
Proxying arbitrary upstream APIs couples Credenza to every resource server
protocol, defeats HTTP-level caching and streaming, and creates a single
chokepoint for all upstream I/O. The correct model is token delegation, not
proxy delegation.

### 4.2 Separate /wallet Endpoint

A dedicated endpoint (e.g., `GET /wallet/{resource_uri}`) for token retrieval,
authenticated by presenting a Credenza session key.

**Rejected**: Redundant with token exchange semantics and introduces a new
authorization surface that duplicates existing policy machinery. RFC 8693 is
already the standard mechanism for this operation; deviating from it without
cause adds implementation and interoperability cost.

### 4.3 Include Upstream Tokens in Session Response

Return upstream tokens alongside the Credenza session in `GET /session`.

**Rejected**: Over-broad disclosure. Every consumer of the session endpoint
(including passive readers like introspection clients) would receive all
upstream tokens, not just the ones a specific client is authorized to use. The
`allowed_token_exchange_targets` policy gate would be bypassed entirely.

### 4.4 New Grant Type

Introduce a new grant type (e.g.,
`urn:credenza:grant-type:upstream-token-vend`) instead of extending token
exchange.

**Rejected**: The operation is semantically identical to token exchange. A
separate grant type would require duplicate client authorization logic,
duplicate endpoint plumbing, and a non-standard extension that clients cannot
discover via RFC 8414 metadata. The dispatch logic in Section 3.1 handles the
difference transparently within the existing grant.

---

## 5. Security Considerations

### 5.1 Token Audience

Upstream dependent tokens are issued by the upstream IDP for a specific resource
server, not for Credenza. Returning these tokens to a client means the client
will present them to a third-party service. This is the intended model -- the
token's audience is the resource server, not an intermediary -- but it differs
from the DERIVED session model where Credenza is always in the authorization
path.

Operators must understand that once an upstream token is vended, Credenza has no
further visibility into how it is used. The `allowed_token_exchange_targets`
gate, combined with `allow_upstream_token_vending`, provides the pre-vend
authorization check; post-vend, enforcement is the resource server's
responsibility.

### 5.2 Token Revocation

Credenza cannot proactively revoke an upstream token that has already been
vended. If the subject session is terminated after vending, the upstream token
remains valid until it expires or is revoked at the upstream IDP. Deployments
with strict revocation requirements should configure short-lived upstream tokens
(online access only, no refresh) and accept that Credenza cannot guarantee
post-vend revocation.

### 5.3 Refresh Token Handling

If a refresh is performed during vending, the new access token and updated
refresh token must be written back to the session store before the response is
returned, to prevent token drift (the next vend for the same resource would
attempt to use the old, now-invalid token). This write-back must be atomic with
respect to concurrent vend requests for the same resource to avoid a refresh
race.

### 5.4 Scope of the Gate

`allow_upstream_token_vending` is a coarse flag. Fine-grained control over
which specific upstream resources a client may vend is provided by
`allowed_token_exchange_targets`. Both must be satisfied.

---

## 6. Implementation Sketch

Affected files (approximate):

- `api/session/augmentation/base_provider.py` -- add `resource_server_index` to
  `process_additional_tokens` output
- `api/auth/client/client_registry.py` -- add `allow_upstream_token_vending:
  bool` to `ClientRecord`
- `rest/token.py` -- extend `_handle_token_exchange_grant()` with dispatch logic
  (Section 3.1) and new vending path (Section 3.2)
- `api/session/storage/session_store.py` -- atomic write-back of refreshed
  tokens (Section 5.3)
- `config/client_registry.sample.json` -- document `allow_upstream_token_vending`

New tests required:

- Upstream token returned when resource matches stored entry
- DERIVED session returned when resource does not match (existing path unchanged)
- Mixed resource request rejected
- Expired token refreshed before vending; refresh token written back
- Expired token with no refresh token returns `invalid_token`
- `allow_upstream_token_vending: false` (default) blocks vending even when
  `allowed_token_exchange_targets` is satisfied
- Concurrent vend requests for the same expired resource do not double-refresh