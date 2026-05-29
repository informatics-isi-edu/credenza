# ADR-0008: Cross-Credenza Federation via Peer Introspection

## 1. Status

**Proposed**
Decision Date: 2026-05-28

### Review History

| Date       | Status   | Notes         |
|------------|----------|---------------|
| 2026-05-28 | Proposed | Initial draft |

---

## 2. Context

### 2.1 The Problem: Introspection Gap (Primary)

When a DERIVED session is issued by Credenza-B but the resource server introspects against Credenza-A, Credenza-A
returns `{"active": false}` because the session is not in its local store.

Concrete deployment that triggered this ADR:

1. User authenticates to **Credenza-B** on mcp.eye-ai.org and receives session key **K-B**.
2. MCP core does token exchange at Credenza-B. K-B is found locally; Credenza-B issues DERIVED session key **K-derived**
   scoped to the DERIVA resource.
3. MCP core calls the DERIVA REST API at dev.eye-ai.org with K-derived as the bearer token.
4. DERIVA validates K-derived against **Credenza-A** (dev.eye-ai.org) -- either via RFC 7662 `/introspect` or the legacy
   `/authn/session` endpoint depending on deployment mode.
5. Credenza-A has no record of K-derived. It was issued by Credenza-B. The validation fails.
6. DERIVA rejects the request.

The token exchange in step 2 succeeded. The DERIVED session is valid at Credenza-B. The failure is entirely in the
introspection step: an opaque session key is only meaningful to the Credenza instance that created it.

The short-term workaround is to set `AUTH_HOSTNAME=dev.eye-ai.org` in the MCP stack environment so that authentication
and token exchange both go through Credenza-A. This causes MCP-issued DERIVED sessions to be held by Credenza-A, making
them introspectable there. This ADR describes the proper fix that eliminates the restriction that all components of a
deployment must share the same Credenza instance.

### 2.2 Symmetric Gap: Token Exchange Direction

There is a symmetric gap in the token exchange direction: if a user's primary session was issued by Credenza-A but the
MCP stack wants to exchange it at Credenza-B, `_handle_token_exchange_grant` at Credenza-B cannot find the subject token
and returns `invalid_token`. This scenario arises if the auth flow is split the other way (user logs in against the
remote credenza, exchange requested at the local one).

Both gaps have the same root cause and the same solution mechanism. This ADR addresses both. The introspection gap (
Section 2.1) is the primary driver; the token exchange gap is addressed in Section 3.3 for completeness.

### 2.3 Existing Machinery

Credenza already implements RFC 7662 Token Introspection at `POST /authn/introspect`. The introspection response
includes `iss`, `sub`, `scope`, `aud`, `exp`, and the full `userinfo` dict. The endpoint requires client authentication
and supports resource-level gating via `allowed_introspection_resources`. This is precisely the mechanism needed for
peer verification in both gaps.

### 2.4 Relationship to ADR-0006

ADR-0006 (Dependent Token Vending) addresses a different case: the subject token is a valid local session, and the
requested resource maps to an upstream IDP token held in escrow in `additional_tokens`. The local store lookup succeeds
in that case. ADR-0008 activates only when the local store lookup fails. The two ADRs extend the same function at
different points in the dispatch logic and do not interact.

---

## 3. Decision

Introduce a **trusted peer introspection fallback** for both affected endpoints. When the local session store lookup
fails, the endpoint attempts RFC 7662 introspection of the presented token against each configured trusted peer Credenza
instance in order. If any peer returns `active: true`, the local endpoint proceeds as if the session had been found
locally.

A shared `TRUSTED_INTROSPECTION_PEERS` configuration controls which peers are trusted and how to authenticate to them.

### 3.1 Peer Configuration

A new optional config key `TRUSTED_INTROSPECTION_PEERS` is introduced (default: empty list). Each entry specifies one
trusted peer:

```json
{
  "TRUSTED_INTROSPECTION_PEERS": [
    {
      "issuer": "https://mcp.eye-ai.org/authn",
      "introspect_url": "https://mcp.eye-ai.org/authn/introspect",
      "client_id": "dev-credenza-peer",
      "client_secret_env": "PEER_CREDENZA_CLIENT_SECRET",
      "timeout_seconds": 5
    }
  ]
}
```

Fields:

- `issuer` -- the peer Credenza's base URL. Used to identify the source in audit logs and to verify the `iss` claim in
  the introspection response.
- `introspect_url` -- full URL of the peer's `/introspect` endpoint.
- `client_id` -- the client ID this Credenza presents when authenticating to the peer's introspect endpoint. This client
  must be registered in the peer's client registry with appropriate `allowed_introspection_resources` (see Section 5.1).
- `client_secret_env` -- name of the environment variable holding the client secret. Secrets are never stored in the
  config file.
- `timeout_seconds` -- per-call network timeout (default: 5). A peer that does not respond within this window is treated
  as inactive and the next peer is tried.

The same peer list is used by both the introspect fallback (Section 3.2) and the token exchange fallback (Section 3.3).

### 3.2 Peer Fallback in /introspect (Primary Gap)

The fallback is inserted in `introspect_token()` in `rest/introspect.py` immediately after the failed local store
lookup:

```python
sid, session = store.get_active_session_by_session_key(token)
if sid is None or session is None:
    peer_response = _peer_introspect(token, req_resources, peers, ssl_verify)
    if peer_response is None:
        return jsonify(_INACTIVE)
    return jsonify(peer_response)
```

`_peer_introspect` tries each configured peer in order and returns the peer's introspection response dict (with the
`active` key already confirmed `True`) on the first match, or `None` if all peers return inactive or fail.

The `resource` parameters from the original introspect request are forwarded to the peer call. This invokes the peer's
own resource binding gate: if the subject token is not bound to those resources at the peer, the peer returns
`{"active": false}` and the local endpoint propagates that result.

**Issuer in the response**: the peer's response is relayed without modification, including the peer's `iss` value. The
resource server trusts the local introspect endpoint (via TLS and client authentication) as the introspection authority;
the `iss` field in the response is an informational claim about where the session was established, not a trust anchor
for the opaque-token model. This is the correct behavior: it accurately describes which Credenza issued the session
without misrepresenting the source.

The existing `allowed_introspection_resources` client gating (checked before the local store lookup) still applies: if
the calling resource server's client record has `allowed_introspection_resources`, the token's `aud` must intersect
those resources. For the federation path, the `aud` comes from the peer's introspection response. The gate is applied
after the peer response is received, not before.

### 3.3 Peer Fallback in /token Token Exchange (Secondary Gap)

The fallback is inserted in `_handle_token_exchange_grant()` in `rest/token.py` immediately after the failed local store
lookup (currently line 533):

```python
sid, session = store.get_active_session_by_session_key(subject_token)
if session is None:
    session = _peer_introspect_as_session(subject_token, target_resources, peers, ssl_verify)
    if session is None:
        abort(400, description=OAuthError.INVALID_TOKEN)
    sid = None  # no local session ID on the federation path
```

`_peer_introspect_as_session` calls the same peer introspection logic but wraps the result in a `RemoteSession`adapter (
see below) instead of returning it directly.

**RemoteSession adapter**: satisfies the interface expected by the remainder of `_handle_token_exchange_grant`:

| Field               | Source in peer introspect response                                      |
|---------------------|-------------------------------------------------------------------------|
| `userinfo`          | response dict minus RFC 7662 structural fields                          |
| `sub`               | `sub` claim                                                             |
| `scopes`            | `scope` claim split on whitespace                                       |
| `allowed_resources` | `aud` claim (list)                                                      |
| `realm`             | matched from `iss` claim against configured peers                       |
| `is_derived()`      | `False` unless `credenza_session_type: "DERIVED"` present (Section 3.4) |

`RemoteSession` is ephemeral and is not written to the local session store. All existing token exchange policy controls
apply in the same order as for a locally found subject token (client auth, `allowed_token_exchange_targets`, scope
no-escalation, transitive exchange check).

### 3.4 credenza_session_type Extension

To support transitive exchange prevention on the token exchange path (Section 3.3), the peer Credenza's `/introspect`
response is extended with one additional field emitted only when the session is derived:

```json
{
  "credenza_session_type": "DERIVED"
}
```

This field is added in `rest/introspect.py` when `session.is_derived()` is true. It is omitted for primary and device
sessions. The field uses a `credenza_` namespace prefix to avoid conflicting with standard claims and is
backward-compatible: existing callers that do not understand it ignore it.

`RemoteSession.is_derived()` returns `True` if and only if `credenza_session_type == "DERIVED"`. Absence of the field
means the session is not derived (the field is only emitted when it is, so absence is authoritative).

This field is also useful in the introspect-path response (Section 3.2) as an informational hint to resource servers
that wish to differentiate primary from derived sessions.

### 3.5 Audit Trail

All peer introspection calls are audit-logged regardless of outcome:

- `peer_introspect_attempt` -- peer `issuer`, calling context (introspect or token_exchange), local `client_id`
- `peer_introspect_active` -- peer `issuer`, `sub`, resources (on success)
- `peer_introspect_inactive` -- peer `issuer`, reason (token not found, resource mismatch, peer error, timeout)

On the token exchange path, the standard `token_exchange_issued` event fires on successful issuance and logs`client_id`,
`sub`, and resources; `sid` will be `None` indicating a federation-sourced exchange.

On the introspect path, the standard `introspect_token_active` event fires, augmented with a `peer_issuer` field
identifying which peer confirmed the token.

---

## 4. Alternatives Considered

### 4.1 AUTH_HOSTNAME Workaround (Status Quo)

Set `AUTH_HOSTNAME=dev.eye-ai.org` in the MCP stack environment so that authentication and token exchange both go
through Credenza-A. MCP-issued DERIVED sessions are then held by Credenza-A and are locally introspectable there.

**Not a permanent solution.** Works for the specific split-deployment scenario but requires all components to route
through a single remote Credenza, prevents the local Credenza from serving as an auth authority in its own right, and
does not help in scenarios where the remote Credenza is not the right auth endpoint (e.g., different organizations). The
federated introspection model removes this constraint while keeping the AUTH_HOSTNAME approach available as a simpler
option for deployments that do not need it.

### 4.2 Shared Session Store

Configure both Credenza instances to use the same Redis or PostgreSQL session store. Any store lookup would find tokens
issued by either instance.

**Rejected.** Tightly couples independent deployments with different operational life cycles and security domains. A
shared store is a single point of failure and creates a combined blast radius. Conflicts with deployments where the peer
Credenza is independently operated.

### 4.3 JWT Tokens Instead of Opaque Keys

Replace opaque session keys with signed JWTs. Any Credenza holding the peer's public key could validate tokens without a
network call.

**Not pursued at this time.** Significant redesign of the session model and all consumers. Opaque tokens provide
revocation guarantees that JWTs inherently lack without a revocation check, which recreates the network dependency. The
RFC 7662 introspection model provides equivalent validation with explicit revocation semantics and is consistent with
the existing architecture.

### 4.4 Token Forwarding / Proxy in Token Exchange

The local Credenza forwards the token exchange request to the peer and returns its response.

**Rejected** for the token exchange direction. The local Credenza would be proxying policy it cannot audit or control.
The resulting DERIVED session would be issued by the remote Credenza and would not be locally introspectable, recreating
the original problem in the opposite direction.

---

## 5. Security Considerations

### 5.1 Peer Trust Boundary

Each entry in `TRUSTED_INTROSPECTION_PEERS` represents an explicit trust decision: this Credenza will act on identity
claims asserted by that peer. The list must be explicitly configured and must not be auto-discoverable or modifiable at
runtime. No peers are trusted by default.

At the peer, this Credenza's `client_id` must be registered with narrowly scoped `allowed_introspection_resources`
covering only the resources the federation is intended to serve. An overly broad introspection grant at the peer allows
this Credenza to validate tokens for resources outside the intended federation scope.

### 5.2 Mutual Configuration

Each side of the federation must independently configure the trust relationship. For the introspect gap (Section 3.2):
Credenza-A must list Credenza-B in its `TRUSTED_INTROSPECTION_PEERS`, and Credenza-B must register Credenza-A as a
client with introspection rights. For the token exchange gap (Section 3.3): Credenza-B must list Credenza-A in its
peers, and Credenza-A must register Credenza-B as a client with introspection rights. The two directions are independent
and can be configured asymmetrically.

### 5.3 Client Secret Management

The `client_secret_env` indirection ensures secrets are not embedded in config files. In Docker deployments, secrets
should be injected via Docker secrets or environment variables, consistent with how `mcp_client_secret` is managed in
the existing stack.

### 5.4 Response Integrity and TLS

All peer introspection calls are made over HTTPS. TLS certificate validation must be enabled for all production peers (
`SSL_VERIFY` must be `true`). The `iss` claim in the peer response must be verified against the configured `issuer`value
to prevent a misconfigured or compromised endpoint from asserting a different issuer identity.

### 5.5 Network Timeout Impact

A slow or unreachable peer adds latency to every request where the local lookup fails. The `timeout_seconds` limit
bounds per-peer delay, but if multiple peers are configured and all are slow, total delay can reach
`N * timeout_seconds`. Only configure peers that are reliably reachable and use a short timeout. Peers are tried in
declaration order; list the most likely peer first.

### 5.6 No Caching of Peer Responses

Peer introspection responses are not cached between requests. Each request that requires peer verification performs a
live introspection call. This is intentional: caching would delay revocation propagation. If the peer revokes a
session (e.g., user logout), the next introspect or exchange request receives `{"active": false}` and is denied.

### 5.7 Scope of DERIVED Sessions on Federation Path

On the token exchange federation path, the locally issued DERIVED session is bound to the exchange client's target
resources, not the peer session's original resources. The peer session's `aud` is used only for scope no-escalation
validation. This is consistent with the existing token exchange resource policy (ADR-0001 Section 5.4, amended
2026-03-19) and prevents cross-instance privilege escalation.

### 5.8 iss Claim in Relayed Introspect Responses

When the introspect path relays a peer response (Section 3.2), the `iss` value in the response reflects the peer
Credenza that issued the session, not the local Credenza serving the request. For the opaque token model this is
accurate: the resource server's trust is established by the introspect endpoint itself (TLS + client authentication),
not by the `iss` claim. The `iss` claim is informational.

However, resource servers that perform strict `iss` validation -- checking that `iss` matches a configured expected AS
URL -- will reject the response. DERIVA operating in legacy mode via `/authn/session` does not return or check `iss` at
all, so this does not affect the primary deployment scenario. For RFC 7662 resource servers that do strict `iss`
checking, operators have two options:

- **Option A (recommended)**: configure the RS to accept both Credenza URLs as valid issuers.
- **Option B**: have the local Credenza rewrite `iss` to its own URL in the relayed response.

Option B is operationally simpler (single issuer URL in RS config) but causes the local Credenza to assert an issuer
identity for a session it did not create. This can cause confusion in audit logs and claim-mapping logic that relies on
`iss` to select realm-specific behavior. Option A is more accurate and is recommended. Option B can be enabled via a
per-peer flag (`rewrite_iss: true`) if a deployment requires it; this ADR does not implement it but leaves the door
open.

---

## 7. Relationship to Formal Federation Standards

This ADR implements AS-to-AS introspection federation using RFC 7662 as the trust-verification primitive. Two formal
standards address the broader problem of multi-AS trust at larger scale; they are described here for context.

### 7.1 OpenID Connect Federation

OpenID Connect Federation (draft-ietf-connect-federation, being finalized) defines automatic trust establishment between
AS instances via signed *Entity Statements* -- JWTs each instance publishes at `/.well-known/openid-federation`
describing its metadata, endpoints, and signing keys. Trust chains are verified from a leaf entity up to a shared *trust
anchor* (an org-level signing key). Any AS whose entity statement chains to a known trust anchor is automatically
trusted, without manual peer configuration.

For Credenza, adopting OIDC Federation would mean:

- Each instance serves `/.well-known/openid-federation` with a signed entity statement
- Each instance manages a per-instance signing keypair (distinct from session signing)
- An org-level trust anchor service enrolls instances and signs their entity statements
- The `TRUSTED_INTROSPECTION_PEERS` config is replaced by dynamic trust chain verification

The `TRUSTED_INTROSPECTION_PEERS` approach in this ADR is a manual, configuration-driven approximation of what OIDC
Federation does automatically. It trades dynamic discovery for explicit, auditable peer lists. For a small number of
controlled instances in a single organization, the manual approach is the right tradeoff. OIDC Federation becomes
relevant when the number of instances grows, when instances cross organizational boundaries, or when adding a new
instance should not require reconfiguring all existing ones.

### 7.2 GNAP (RFC 9635)

GNAP (Grant Negotiation and Authorization Protocol) is a new authorization framework intended as a long-term successor
to OAuth 2.0. It defines AS-to-RS and AS-to-AS interactions as first-class protocol primitives, including a generalized
back-channel by which a resource server can verify any token by sending a structured request to its issuing AS. This
makes cross-AS token validation a native capability rather than an extension.

For Credenza, GNAP would require redesigning the entire grant model -- it is not a federation add-on but a wholesale
protocol replacement. It is not applicable to the specific problem addressed by this ADR. It is noted here because it
represents where the standards community expects the long-term solution space to land.

---

## 9. Implementation Sketch

Affected files:

- `credenza/rest/introspect.py` -- (a) add `credenza_session_type: "DERIVED"` to response when `session.is_derived()` is
  true; (b) after failed local lookup, call `_peer_introspect()` and return its response if active; apply existing
  `allowed_introspection_resources` client gating using `aud` from the peer response
- `credenza/api/common/peer_introspect.py` -- new module: `PeerConfig` dataclass;
  `_peer_introspect(token, resources, peers, ssl_verify) -> dict | None` (returns raw peer response dict or None);
  `RemoteSession` adapter (for token exchange path only);
  `_peer_introspect_as_session(token, resources, peers, ssl_verify) -> RemoteSession | None`
- `credenza/rest/token.py` -- in `_handle_token_exchange_grant()`: after failed local lookup, call
  `_peer_introspect_as_session`; pass resulting `RemoteSession` through existing policy unchanged; `sid = None` on
  federation path
- `credenza/app.py` -- load `TRUSTED_INTROSPECTION_PEERS` from config, resolve `client_secret_env` references, attach to
  `app.config["TRUSTED_INTROSPECTION_PEERS"]`
- `config/credenza.sample.json` -- document `TRUSTED_INTROSPECTION_PEERS` with example entry
- `test/rest/test_introspect.py` -- new tests for introspect federation path
- `test/rest/test_token.py` -- new tests for token exchange federation path

New tests required:

**Introspect path (test_introspect.py):**

- Token issued by peer → local introspect calls peer, returns active response with peer's `iss`
- Token not found locally or at any peer → `{"active": false}`
- Peer `allowed_introspection_resources` gate: resource param forwarded to peer call
- Local `allowed_introspection_resources` client gating applied to peer `aud`
- Peer timeout → tries next peer; all timeout → `{"active": false}`
- `iss` mismatch in peer response → peer response rejected
- `TRUSTED_INTROSPECTION_PEERS` empty → local-only behavior unchanged

**Token exchange path (test_token.py):**

- Subject token found via peer introspection → local DERIVED session issued
- Subject token not found locally or at any peer → `invalid_token` (400)
- Peer returns `credenza_session_type: "DERIVED"` → transitive exchange denied (403)
- `TRUSTED_INTROSPECTION_PEERS` empty → existing local behavior unchanged
- All existing token exchange tests for locally found subjects are unaffected