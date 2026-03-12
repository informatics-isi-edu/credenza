# ADR-0002: Optional Consent UI with Delegation Transparency

## 1. Status

**Proposed**
Decision Date: 2026-03-12

### Review History

| Date       | Status   | Notes                                                              |
|------------|----------|--------------------------------------------------------------------|
| 2026-03-12 | Proposed | Initial draft covering authorization and delegation consent design |

---

## 2. Context

ADR-0001 explicitly states that Credenza SHALL NOT implement a consent UI,
deferring authorization policy entirely to upstream IDPs and admin-time
client registry configuration. This was appropriate for the initial narrow
OAuth AS scope, where all clients are first-party or internally administered.

Two developments motivate revisiting this decision:

### 2.1 External and Semi-Trusted Clients

As Credenza gains adoption as an OAuth AS, the client population may expand
beyond fully first-party integrations. Even in controlled deployments, there
is a distinction between:

- **First-party clients**: Internal tools built and operated by the same
  organization. Admin registration implies full trust. No runtime consent
  needed.
- **Semi-trusted clients**: External or third-party tools that authenticate
  via Credenza but are not operated by the same team. Admin registration
  permits them to exist; runtime consent informs the user of what they are
  authorizing.

### 2.2 Delegation Transparency

The more significant driver is delegation via token exchange (RFC 8693).

In the MCP deployment model:

1. A user authorizes an MCP client to access the MCP RS.
2. The MCP RS later exchanges the user's token for a derived token scoped
   to a downstream service (e.g., DERIVA catalog APIs).
3. The MCP RS calls that downstream service as the user, without any
   further user interaction.

Under the current model, the user has no visibility into step 2 or 3. They
authorized the MCP client to access the MCP RS; they did not explicitly
authorize the MCP RS to impersonate them downstream.

This is not a security flaw -- the token exchange policy is enforced via
`allowed_token_exchange_targets`, which is admin-controlled and default-deny.
The user cannot be impersonated by any service not explicitly permitted in
the registry. However, it is an **informed consent gap**: the user does not
know, at authorization time, that their identity will be delegated further.

Standard OAuth scope consent ("this app wants to read your email") does not
cover this. Scopes describe what the client can access; they do not describe
downstream delegation chains. These are genuinely different consent surfaces.

### 2.3 Relationship to ADR-0001

This ADR does not replace ADR-0001. It partially revises the "no consent UI"
position in a targeted way:

- The general principle (no rich authorization policy UI, no role engines,
  no dynamic scope negotiation) is preserved.
- A narrow, optional consent mechanism is introduced for delegation
  transparency and external client authorization.
- First-party internal clients continue to operate without any consent UI.

---

## 3. Decision

Credenza SHALL introduce an optional, policy-driven consent mechanism
controlled entirely by client registry configuration.

### 3.1 Two Consent Surfaces

Two distinct consent surfaces are defined, presented together in a single
consent page when applicable:

**Authorization consent** -- the user approves the client's request to
access a resource server on their behalf. Analogous to standard OAuth
consent but limited to what is already policy-bounded in the registry
(no free-form scope grant negotiation).

**Delegation consent** -- the user is informed that the resource server
they are authorizing can impersonate them downstream, via token exchange,
when accessing other services. This is surfaced by Credenza automatically
based on the RS's `allowed_token_exchange_targets` configuration.

Delegation consent is the primary motivation for this ADR. Authorization
consent is a natural companion and covers the semi-trusted client case.

### 3.2 Consent Is Opt-In Per Client

Consent is gated by a `require_consent` field on `ClientRecord`:

- `require_consent: false` (default for internal clients) -- no consent
  page is shown; the flow proceeds as it does today.
- `require_consent: true` -- a consent page is presented before the
  authorization code is issued. Applies to both authorization and
  delegation surfaces.

First-party clients SHALL continue to set `require_consent: false`.
No behavior change occurs for any existing client registration.

### 3.3 Consent Is Stored Per User Per RS

Granted consent is stored and reused within a configurable TTL (default:
90 days) to avoid re-prompting on every login.

Consent is keyed by `(sub, rs_resource_uri)` rather than
`(sub, client_id)` for delegation consent, because the delegation
capability belongs to the RS, not the client. A user who grants
delegation consent for a given RS does not need to re-grant it when
a different client later requests a token for the same RS.

Authorization consent (client-level) is keyed by `(sub, client_id)`.

Both keys are checked at consent evaluation time. The consent page is
only shown if either key is missing or stale.

### 3.4 Consent Covers Maximum Permitted Delegation, Not Actual Use

The delegation consent page shows the full set of downstream services
the RS is permitted to reach via token exchange (`allowed_token_exchange_targets`).
It does not attempt to infer which downstream services will actually be
called for a given user session. This is consistent with how standard OAuth
scope consent works -- users consent to the maximum permitted capability.

### 3.5 Consent Does Not Expand Permissions

The consent UI is informational and confirmatory. It does not allow users
to grant permissions beyond what the admin has configured. A user cannot
consent to exchange targets that are not in `allowed_token_exchange_targets`.
A user cannot consent to scopes not in `allowed_scopes`. Deny is an option;
custom grant is not.

---

## 4. Architecture

### 4.1 Insertion Point

Consent is evaluated in `login.py`'s `callback()`, after the user has
been authenticated by the upstream IDP and userinfo is available, but
before the authorization code is issued.

The existing code path:

```
IDP authenticates user
  -> callback()
  -> [oauth flow?] -> issue auth code -> redirect to client
```

With consent inserted:

```
IDP authenticates user
  -> callback()
  -> [oauth flow?]
       -> [require_consent?] --(no)--> issue auth code -> redirect to client
                |
               yes
                -> [consent already on record?] --(yes, covers request)--> issue auth code -> redirect to client
                                |
                               no
                                -> store pending state
                                -> redirect browser to GET /authorize/consent
                                        |
                                   render consent page
                                        |
                                   POST /authorize/consent
                                        |
                            +-----------+-----------+
                           deny                  approve
                            |                       |
                    redirect to client        store consent record
                    error=access_denied       issue auth code
                                              redirect to client
```

### 4.2 Pending Consent State

Because consent interrupts an in-progress callback, all authentication
results must be persisted temporarily while the user interacts with the
consent page. A `pending_consent` key type is introduced in the session
store, distinct from authorization codes and session records.

Pending consent records:
- Are keyed by a random token (`token_hex(16)`) passed as a query parameter
- Have a short TTL (default: 5 minutes)
- Are atomically consumed (read-and-delete) when the consent form is submitted
- Contain: `sub`, `userinfo`, `session_id`, `authn_request_ctx`, upstream tokens

Upstream tokens in the pending record are subject to the same TTL and
should not be stored beyond what is necessary to complete the auth code
issuance at consent completion.

### 4.3 Delegation Target Lookup

To display delegation targets, Credenza must determine which RS is
being authorized (from the `resource` parameter in `/authorize`) and
look up that RS's `allowed_token_exchange_targets`.

This requires a reverse index on the client registry: given a resource
URI, find the client record that controls that resource. `ClientRegistry`
SHALL maintain an inverted index built at load time:

```python
def find_rs_by_resource(self, resource_uri: str) -> ClientRecord | None:
    ...  # O(1) lookup via pre-built index
```

An RS whose `allowed_token_exchange_targets` is empty or absent has no
delegation capability to disclose. No delegation consent panel is shown
for such RS registrations.

### 4.4 New ClientRecord Fields

```python
require_consent: bool = False
display_name: str = ""                       # human-readable name for consent page
scope_descriptions: dict[str, str] = {}     # {"openid": "Your identity", ...}
```

### 4.5 New Session Store Operations

```python
# Pending consent -- bridges callback to consent page
store.set_pending_consent(key: str, data: dict, ttl: int)
store.get_and_consume_pending_consent(key: str) -> dict | None  # atomic

# Granted consent records
store.set_consent(sub: str, client_id: str, rs_resource: str,
                  scopes: set, resources: set, ttl: int)
store.get_consent(sub: str, client_id: str, rs_resource: str) -> dict | None
```

### 4.6 New Consent Blueprint

A new `consent.py` blueprint handles the consent page and form submission:

`GET /authorize/consent?pending=<key>`
- Loads pending state (peek, do not consume)
- Loads client record and RS record from registry
- Renders consent page: client display name, resource summary,
  delegation targets (if any)

`POST /authorize/consent`
- Atomically consumes pending state
- On deny: redirects to `redirect_uri?error=access_denied&state=<state>`
- On approve: stores consent record(s), issues authorization code,
  redirects to `redirect_uri?code=<code>&state=<state>`

The consent page SHALL be rendered via a configurable template path
(defaulting to a built-in template) so that operators can apply
their own branding.

---

## 5. What This Does Not Change

- First-party clients (`require_consent: false`) -- no behavior change.
- `client_credentials` grant -- no user is involved; consent is meaningless.
- Device flow -- user interaction occurs at the IDP browser step; consent
  could be layered in at the verify/callback stage if needed but is
  out of scope for this ADR.
- Token exchange itself -- the exchange policy (`allowed_token_exchange_targets`,
  default-deny, non-transitive) is unchanged. Consent is informational;
  it does not alter what exchanges are permitted.
- Introspection, revocation, metadata -- unchanged.

---

## 6. Acceptance Criteria

This ADR moves from Proposed to Accepted when:

1. `require_consent` field is implemented on `ClientRecord`.
2. `pending_consent` store operations are implemented and atomically consumed.
3. Consent records are stored and reused within TTL, keyed correctly.
4. `ClientRegistry.find_rs_by_resource()` inverted index is implemented.
5. Consent page renders correctly for both authorization and delegation
   surfaces, including when `allowed_token_exchange_targets` is empty.
6. Deny path redirects with `error=access_denied`.
7. First-party clients with `require_consent: false` are unaffected.
8. Tests cover: consent bypass (first-party), consent shown (external),
   consent reuse within TTL, deny path, delegation panel present/absent.

---

## 7. Consequences

### Positive

- Users are explicitly informed when an RS will impersonate them downstream.
- Consent model is extensible to semi-trusted external clients without
  changing the internal client experience.
- Delegation transparency is surfaced at exactly the right moment -- before
  any downstream access occurs, and within the same browser session as
  the original authentication.
- Consent is stored and reused; UX friction is low for repeat logins.

### Negative

- Additional session store complexity (pending consent, consent records).
- Consent page adds a round-trip in the authorization code flow for
  affected clients.
- Pending state TTL creates a narrow window where authentication results
  are held in store but not yet committed to a session -- this must be
  accounted for in storage backend sizing and TTL policy.
- Delegation consent shows maximum capability, not actual use, which
  may be confusing for users if the RS has a large `allowed_token_exchange_targets`
  list.

---

## 8. Alternatives Considered

### 8.1 IDP-Level Consent Only

Rely entirely on upstream IDP consent screens. Rejected because IDP
consent covers IDP-level scopes and claims; it has no visibility into
Credenza's token exchange topology or downstream delegation.

### 8.2 Out-of-Band Consent (Terms of Service)

Require users to accept a ToS that describes the delegation model.
Rejected because it is not contextual -- the user is not told at
authorization time which specific downstream services will be reachable.

### 8.3 Audit Logging as Substitute for Consent

Log all token exchange events and make them available to users on request.
Considered as a complement, not a substitute. Audit logging is already
present; it does not address the informed consent gap at authorization time.

### 8.4 Universal Consent for All Clients

Require consent for all clients, including first-party. Rejected because
it imposes UX friction with no security benefit for internally administered
tools where admin registration is already the authorization decision.

---

## 9. Summary

Credenza introduces a narrow, optional consent mechanism targeting two
gaps not covered by admin-time registry configuration alone: authorization
transparency for semi-trusted clients, and delegation transparency for
token exchange chains. The mechanism is opt-in per client registration,
preserves all existing behavior for first-party clients, and surfaces
delegation capability information at the point of authorization rather
than retroactively. The underlying token exchange policy and enforcement
model is unchanged.