# ADR-0010: M2M Client Credential Provisioning CLI (`credenza-manage`)

## 1. Status

**Proposed**
Decision Date: 2026-09-01

### Review History

| Date       | Status   | Notes         |
|------------|----------|---------------|
| 2026-09-01 | Proposed | Initial draft |

---

## 2. Context

### 2.1 The Problem

webauthn2 (DERIVA's legacy session broker, being replaced by Credenza per ADR-0009) has
long supported a standalone local-testing posture that its eventual deprecation puts at
risk: a scripted setup with no dependency on an external IDP, used for non-routed
dev-machine and CI/GitHub-workflow test scenarios. Concretely, that workflow is:

1. Scripted setup/provisioning of the standalone stack.
2. Scripted provisioning of test accounts and attributes (e.g. an admin role).
3. Scripted session provisioning, storing session credentials into distinct cookie
   files.
4. Running actual client code (the ermrest test suite, curl, python-requests) against
   the stack using those credential files, sometimes juggling multiple distinct
   credential files across test cases in the same run.

`webauthn2-manage` (`webauthn/bin/webauthn2-manage`) supports this today via `adduser`/
`passwd`/`addattr`/`assign` (local "database" provider, steps 1-2) and `addrobot`
(fabricates an identity and a session credential file in one call, collapsing steps
2-3). The concern: does Credenza have an equivalent, or does dropping webauthn2 force
every standalone/CI test scenario to stand up a full IDP (Keycloak, etc.) just to run
local tests?

### 2.2 What Credenza Already Provides

- **No upstream IDP required.** The `client_credentials` grant
  (`_handle_client_credentials_grant()`, `credenza/rest/token.py:178-238`) authenticates
  a registered `ClientRecord` purely against `client_registry.json` via the
  `client_secret` adapter (`credenza/api/auth/client/adapters/impl/client_secret.py`) --
  no network call to any IDP.
- **Bearer header and cookie are interchangeable.** `extract_session_key()`
  (`credenza/api/common/util.py:38-43`) checks `Authorization: Bearer <token>` first,
  then falls back to the cookie named `COOKIE_NAME` (`"credenza"`, or `"webauthn"` in
  legacy mode -- `credenza/app.py:115-116`). Both resolve the same opaque value through
  `store.get_active_session_by_session_key()`. deriva-py's own
  `DerivaBinding.set_credentials()` (`deriva-py/deriva/core/deriva_binding.py:215-227`)
  natively accepts either a `cookie` or `bearer-token` key, so a single minted token
  serves both channels without any translation step.
- **Fabricated roles/claims flow through untouched.** `additional_claims` configured on
  a `ClientRecord` are merged into the issued session's userinfo via `merge_userinfo()`
  (`credenza/rest/token.py:229`), the same dict a real login would populate. `sub` is
  deterministic -- it's the client_id itself (`client_secret.py:161`).
  `session_type` (SERVICE vs USER) never appears in `make_session_response()`'s output
  (`credenza/rest/session.py:277-362`), so a resource server reading `GET`/`PUT
  /session` cannot distinguish a `client_credentials`-issued identity from a real login.
- **Resource binding is satisfied by the real DERIVA-side proxy.** SERVICE sessions
  enforce a resource-binding check on every `/session` call
  (`credenza/rest/session.py:75-118`): the caller's `resource=` query params must
  intersect `session.allowed_resources`. `ClientSessionCachedProxy`
  (`webauthn/webauthn2/util.py`), which is what ermrest/hatrac actually use to validate
  sessions (a `deriva-serverlib` migration is in progress to replace it, but this is
  today's mechanism), always appends `resource=` on every `PUT /authn/session` call,
  defaulting to `["urn:deriva:rest:service:all"]` (`add_resources()`). So a client whose
  `default_resources` includes that URI satisfies the check automatically, with no
  explicit `resource=` needed at token-request time -- `validate_resources_for_client()`
  (`credenza/rest/token.py:672-728`) falls back to `default_resources` when the token
  request doesn't specify one.
- **Compatible with the proxy's PUT-based lifetime extension.** The `PUT /session`
  branch for `is_service()` sessions clamps TTL rather than calling `can_extend()`
  (`session.py:147-164`), so it already tolerates the proxy's "PUT to extend session
  lifetime" call pattern.

In short: one `ClientRecord` per M2M identity (client_secret adapter, `additional_claims`
for roles/groups, `default_resources` matching the deployment's `session_resource_ids`)
already gets a caller a fully-formed session with zero upstream IDP dependency, via a
single `client_credentials` POST -- functionally equivalent to `webauthn2-manage
addrobot` for the fabricated-test-identity case, and equally usable for any other M2M
service credential Credenza is meant to issue.

### 2.3 The Gap

What's missing is tooling, not capability, and the gap isn't specific to testing:

- `client_registry.json` has no management CLI at all. Every `ClientRecord` today is
  hand-edited JSON, including the secret-hashing step (`credenza/api/common/crypto.py`
  has a verify-side hasher registry but no generator). `webauthn2-manage` provides
  `adduser`/`passwd`/`addattr` against a live database; there is nothing equivalent for
  Credenza's registry file, for a test persona or for any other M2M client.
- Nothing mints a token and writes it out in the shape existing client code expects.
  deriva-py's `get_credentials()` reads a JSON file keyed by hostname
  (`{hostname: {"cookie": "name=value"}}` or `{hostname: {"bearer-token": token}}`) --
  the same shape `webauthn2-manage addrobot` already produces. Credenza has no
  equivalent producer, for test personas or for a real M2M service being onboarded.

This ADR proposes a single CLI, `credenza-manage`, to close both gaps as a
general-purpose registry/credential tool. Standalone/CI test-identity provisioning
(Section 2.1) is the scenario that surfaced the need and is used throughout as a
worked example, but the tool itself is not test-specific: it is the convenient way to
provision *any* M2M client's registry entry and mint credentials for it, the same way
an operator would today by hand-editing `client_registry.json` and running a manual
`curl` against `/token`.

---

## 3. Decision

Add `credenza-manage`: a CLI that manages `ClientRecord` entries directly in
`client_registry.json` (secret hashing included) and mints `client_credentials` tokens
into deriva-py-compatible credential files.

### 3.1 Location, Packaging, and Style

Introduce a repo-root `bin/` directory, mirroring `webauthn/bin/`'s layout (Credenza
currently has no `bin/` and no installed console scripts):

- `bin/credenza-manage` -- new script.
- `pyproject.toml` gains `[tool.setuptools] script-files = ["bin/credenza-manage"]`.
  This is the setuptools mechanism for installing a file verbatim onto `PATH` (as
  opposed to `[project.scripts]`/`console_scripts`, which requires an importable
  `module:function` target). It's the right fit here specifically because the script
  is a single self-contained file with a `def main(argv=None)` guarded by
  `if __name__ == "__main__"` -- no refactor into an importable package is needed;
  `pip install .` (or `-e .`, the repo's existing dev install step) puts
  `credenza-manage` on `PATH` as-is.

`credenza-manage` is built on Python's stdlib `argparse`, with one subparser per
command (`add_subparsers()`) -- the same pattern deriva-py's own
`credenza_auth_utils.py`/`CredenzaAuthUtilCLI` already uses, and a better fit than
hand-rolled `sys.argv` parsing given how many optional flags several of these
subcommands take (Section 3.4). Its command *vocabulary* borrows from
`webauthn2-manage` (one verb per action, positional arguments where the schema
allows it), adapted because `ClientRecord` has substantially more fields than a
webauthn2 user row.

The credential-minting subcommand (Section 3.4) performs a real HTTP
`client_credentials` POST via `requests`, exactly what a real client would send -- it
never fakes the grant path in-process, so it exercises the same adapter authentication
and resource validation a real consumer would hit, and surfaces resource-binding
misconfiguration (Section 2.2) at provisioning time rather than at first real use.

`credenza-manage` imports Credenza internals directly where server-fidelity matters:
`credenza.api.auth.client.client_registry.load_client_registry` (validation),
`credenza.api.common.grant_type.GrantType` (canonical grant-type strings), `bcrypt`
(already a core dependency in `pyproject.toml`, no new dependency needed).

### 3.2 Registry File Handling

The CLI edits the **raw JSON document** (`{"version": ..., "clients": {...}}`) directly
with `json.load`/`json.dump`, changing only the fields a given subcommand touches. It
does not build entries by constructing `ClientRecord` objects and serializing them
back: `load_client_registry()` (`client_registry.py:443-539`) fills in defaults,
normalizes list fields, and attaches a computed `fingerprint`, so round-tripping
through it would rewrite an operator's hand-edited entry rather than preserve it.
`load_client_registry()` is used only for post-write validation, described next.

- After every write, the result is reloaded through the real `load_client_registry(path)`
  to catch schema violations immediately (e.g. `default_resources` not a subset of
  `allowed_resources`, enforced in `ClientRecord.__post_init__`,
  `client_registry.py:244-256`) using the server's own validation rather than
  reimplementing it. On failure, the pre-write backup is restored and the error is
  reported.
- Writes are atomic: written to `<path>.tmp`, then `os.replace()` over the target, with
  one `<path>.bak` snapshot of the pre-write content kept for manual recovery.

### 3.3 Secret Handling

- Secrets are generated with `secrets.token_urlsafe(32)` when not supplied, the same
  convention already used for session keys (`session_store.py:141`).
- Stored as `"bcrypt:" + bcrypt.hashpw(secret.encode(), bcrypt.gensalt()).decode()`,
  matching the `stored.startswith("bcrypt:")` prefix convention
  `verify_secret_candidate()`/`_bcrypt` already expect (`crypto.py:105-123, 144-178`).
- Plaintext secrets are never written to the registry file and are echoed to stdout
  exactly once, at the moment of generation or rotation -- capturing it is the
  operator's responsibility, matching `webauthn2-manage passwd ... random`.
- Only confidential (`client_secret` adapter) clients are supported. A `--public`
  (no-secret/PKCE) option is deliberately not built: `client_credentials` always
  requires adapter authentication, so a public client cannot use the minting
  subcommand -- adding that option now would be unused surface.

### 3.4 Subcommands

```
credenza-manage add-client <client_id>
    [--desc <text>] [--realm <realm>]
    [--resources urn:a,urn:b]      (default: urn:deriva:rest:service:all;
                                     sets both allowed_resources and default_resources)
    [--scopes a,b]                 (default: []; sets both allowed_scopes and default_scopes)
    [--max-session-ttl <seconds>]
    [--secret <value>]             (default: auto-generate, printed once)
    [--claims '<json object>']     (seeds additional_claims, e.g. '{"roles":["admin"]}')

    Create a ClientRecord (client_secret adapter,
    allowed_grant_types=["client_credentials"]). Prints the client's secret once if
    generated.

credenza-manage del-client <client_id>
    Remove a client entry.

credenza-manage secret <client_id> [<new-secret>|random]
    Rotate a client's secret (mirrors webauthn2-manage's passwd). Prints the new
    secret once if generated.

credenza-manage set-claim <client_id> <key> <json_value>
credenza-manage unset-claim <client_id> <key>
    Incrementally edit additional_claims after creation, e.g.:
      set-claim test-admin roles '["admin","curator"]'

credenza-manage list
credenza-manage show <client_id>
    Inspect the registry. Secrets always redacted to "<hash present>".

credenza-manage mint <client_id> <hostname>
    [--secret <value> | --secret-file <path> | prompt via getpass]
    [--resource urn:... (repeatable, default urn:deriva:rest:service:all)]
    [--scope <name> (repeatable)]
    [--ttl <seconds>]
    [--cookie-name <name>]          (default: credenza; use "webauthn" for legacy deployments)
    [--deriva-cred <path>]          (also write/merge a deriva-py credential file)
    [--bearer]                      (deriva-cred form: bearer-token instead of cookie)
    [--cookiejar <path>]            (also write/merge a Netscape-format cookie file)

    POSTs a real client_credentials grant to https://<hostname>/token and prints the
    raw access token to stdout -- nothing else -- so it can be captured directly
    (TOKEN=$(credenza-manage mint ...)), exported, or piped, without assuming any
    particular client format.

    --deriva-cred writes/merges <path> in deriva-py's credential shape:
      default:  {hostname: {"cookie": "<cookie-name>=<token>"}}
      --bearer: {hostname: {"bearer-token": <token>}}
    (per deriva-py/deriva/core/deriva_binding.py:215-227 set_credentials(), and the
    per-hostname dict lookup in get_credentials()). Merges into any existing JSON
    content in <path> for other hostnames, the same way credenza-device-helper's
    store_credential() does.

    --cookiejar writes/merges a Netscape-format cookie file at <path> (domain
    <hostname>, name <cookie-name>, value <token>) via the stdlib
    `http.cookiejar.MozillaCookieJar`, directly usable as `curl -b <path>` or loaded
    into a `requests.Session` -- the format the ermrest test-suite workflow in
    Section 2.1 already juggles multiple credential files as.

    --deriva-cred and --cookiejar are independent and may both be given; neither is
    required, and stdout output happens regardless.
```

`mint` has no "extend existing session" mode (unlike `webauthn2-manage addrobot`):
`client_credentials` always mints a fresh, independent token, so there is no
session-extension concept for this grant type -- each call is simply a fresh mint, not
a gap in the tool. `mint` works for any registered confidential client, not just
fabricated test identities -- it's the same action an operator would otherwise perform
by hand with `curl` against `/token`.

There is no `reload` subcommand (Section 3.5): a script calling `add-client` then
`mint` against a deployment with `CLIENT_REGISTRY_RELOAD_INTERVAL` set must still wait
at least that many seconds between the two calls, or `mint` will fail against the
not-yet-reloaded registry.

### 3.5 Registry Hot-Reload

`app.config["CLIENT_REGISTRY"]` is loaded exactly once, at `create_app()` time
(`credenza/app.py:128-129`), and never revisited. Without a reload path, every
`credenza-manage add-client`/`secret`/`set-claim` call is invisible to a running
server until it is restarted -- silently breaking the scripted-provisioning story this
CLI exists for.

**Rejected: a local signal or watched-file trigger.** Better than a network endpoint
(no new network-reachable action, no standing secret), but it still requires PID or
signal-delivery plumbing, and process managers used in real deployments (mod_wsgi,
gunicorn) already reserve `SIGHUP` for their own worker-lifecycle semantics, making a
custom in-app handler for it fragile and deployment-specific to verify.

**Decision: opt-in, TTL-bounded mtime check at the point of use, no trigger at all.**
Introduce a `get_client_registry(app)` accessor that replaces every direct
`current_app.config["CLIENT_REGISTRY"]` read (9 call sites across `token.py`,
`authorize.py`, `introspect.py`, `device.py`, `consent.py`, `login.py`). When a new
config value `CLIENT_REGISTRY_RELOAD_INTERVAL` (seconds, default `0`) is nonzero, the
accessor stats the registry file at most once per interval (a monotonic-clock gate, not
a per-request stat) and reloads via the real `load_client_registry()` if its mtime has
advanced:

```python
def get_client_registry(app) -> ClientRegistry:
    interval = app.config.get("CLIENT_REGISTRY_RELOAD_INTERVAL", 0)
    if not interval:
        return app.config["CLIENT_REGISTRY"]

    now = time.monotonic()
    if now - app.config.get("_CLIENT_REGISTRY_CHECKED_AT", 0) < interval:
        return app.config["CLIENT_REGISTRY"]

    with _registry_reload_lock:
        if time.monotonic() - app.config.get("_CLIENT_REGISTRY_CHECKED_AT", 0) < interval:
            return app.config["CLIENT_REGISTRY"]
        app.config["_CLIENT_REGISTRY_CHECKED_AT"] = time.monotonic()

        path = app.config.get("CLIENT_REGISTRY_FILE", "config/client_registry.json")
        try:
            mtime = os.path.getmtime(path)
        except OSError:
            return app.config["CLIENT_REGISTRY"]
        if mtime <= app.config.get("_CLIENT_REGISTRY_MTIME", 0):
            return app.config["CLIENT_REGISTRY"]

        try:
            reloaded = load_client_registry(path)
        except Exception as ex:
            logger.error(f"client_registry_reload_failed: {ex}")
            audit_event("client_registry_reload_failed", error_type=type(ex).__name__)
            return app.config["CLIENT_REGISTRY"]  # keep serving the last-good registry

        app.config["CLIENT_REGISTRY"] = reloaded
        app.config["_CLIENT_REGISTRY_MTIME"] = mtime
        audit_event("client_registry_reloaded", client_count=len(reloaded.clients))
        return reloaded
```

This closes the gap with no new authorization surface at all, because there is no
separate trigger action to authorize:

- **Default-off, matching this codebase's convention for anything that changes runtime
  behavior automatically** (the same fail-closed-by-default posture as
  `allowed_introspection_resources` and the admin-claim gates elsewhere). Production
  deployments that want "registered clients can't change without a deliberate
  restart" as an implicit control keep exactly that, unchanged.
- **A standalone/CI deployment opts in** with a short interval (e.g. `1` or `2`
  seconds). A script pausing for at least that interval between `credenza-manage
  add-client` and `credenza-manage mint` needs no explicit reload subcommand and no
  endpoint to call -- reproducing the `webauthn2-manage` CI script's shape (Section
  2.1): every provisioning step is a plain CLI call, with a short wait replacing what
  would otherwise be a service-restart step.
- **Fails safe on a bad edit.** If a hand-edited or partially-written registry fails
  `load_client_registry()`'s validation, the server logs and audits the failure and
  keeps serving the last-known-good registry rather than breaking every request that
  touches it. This is a meaningful improvement over an admin endpoint, where a bad
  reload call could otherwise 500 the endpoint or leave the app in a broken state if
  not handled just as carefully.
- **No torn reads.** `credenza-manage`'s own atomic write (`<path>.tmp` +
  `os.replace()`, Section 3.2) guarantees the mtime jump always corresponds to a
  complete, valid JSON file.
- **Bounded overhead.** At most one `os.path.getmtime()` call per
  `CLIENT_REGISTRY_RELOAD_INTERVAL` seconds, process-wide -- not per request.

Known limitation, explicitly out of scope: in a multi-worker deployment
(`processes>1`), each worker independently loads and independently polls, so a change
becomes visible worker-by-worker rather than atomically across the fleet -- the same
class of process-local-state limitation `FixedWindowJitterLimiter`
(`credenza/api/common/rate_limit.py`) already has for rate limiting in multi-worker
deployments. This is a non-issue for `processes=1` (the standalone/CI target of this ADR,
per `config/wsgi_credenza.conf.in`); a multi-worker production deployment should keep
`CLIENT_REGISTRY_RELOAD_INTERVAL=0` and manage registry changes via deliberate
restarts, as it does today.

### 3.6 Example: Standalone/CI Test-Identity Provisioning

Applying the general-purpose tool to the scenario in Section 2.1:

| Step                                    | Mechanism                                                                            |
|-----------------------------------------|--------------------------------------------------------------------------------------|
| 1. Scripted stack setup                 | Unchanged -- existing standalone/Compose provisioning                                |
| 2. Provision test accounts + attributes | `credenza-manage add-client <persona> --claims '{"roles":["admin"]}'`                |
| 2b. Wait for the registry to reload     | Sleep >= `CLIENT_REGISTRY_RELOAD_INTERVAL` (Section 3.5) before step 3               |
| 3. Provision session, store cred file   | `credenza-manage mint <persona> <hostname> --cookiejar <file>`                       |
| 4. Run client code against cred files   | Unchanged -- curl/python-requests already read Netscape-format cookie files          |

Steps 2 and 3 remain two calls rather than one (`webauthn2-manage addrobot` collapses
them into one because webauthn2's local "database" provider and its session mechanism
are the same subsystem). Splitting them here is intentional and generalizes beyond
testing: a client's registry entry (roles, resources, scopes) is durable,
version-controllable policy state meant to be defined once and reused; minting a
credential from an existing entry is a cheap, repeatable action that shouldn't require
re-specifying that policy every time -- true whether the client is a disposable CI
persona or a long-lived production service integration.

---

## 4. Alternatives Considered

### 4.1 In-Process Session Minting (Bypass HTTP)

Have the CLI import `SessionStore` and call `create_session()` directly, skipping the
HTTP round-trip and adapter authentication.

**Rejected.** This would not exercise the actual grant/adapter/resource-validation code
a real client goes through, making the tool less faithful to what a real consumer
experiences and more likely to drift from server behavior over time. `mint` performs a
genuine HTTP POST for the same reason `credenza-device-helper` always does.

### 4.2 Standalone Local IDP (Keycloak Dev Realm, etc.)

Stand up a lightweight Keycloak (or similar) instance pre-seeded with test users for
every standalone/CI scenario, as a drop-in replacement for webauthn2's local "database"
provider.

**Rejected as the default path.** This is exactly the overhead Section 2.1 is trying
to avoid (deploying a full IDP just to run local tests). It remains a valid
option for scenarios that specifically need to exercise the OIDC login/callback path
itself (e.g. testing claim-mapping or consent UI), but is unnecessary for the
credential-provisioning scenario this ADR addresses.

### 4.3 Store the Client Registry in the Persistent Session Store

Instead of a hot-reloaded file (Section 3.5), move `ClientRecord` entries into the
same backend that already holds sessions (Redis/Valkey, PostgreSQL, SQLite, Memory),
so `credenza-manage` writes would be visible immediately with no polling at all.

**Deferred, not pursued in this ADR.** Two problems, not one:

- **Durability coupling.** Sessions are disposable by design -- losing them just means
  affected users log in again. The registry is authoritative, non-regenerable
  configuration: every M2M client, its secret hash, and its policy. Today, a
  deployment's session-store backend is chosen based on how much it matters if
  sessions disappear (of the four supported backends -- Memory, Redis/Valkey,
  PostgreSQL, SQLite -- only Memory and Redis/Valkey are treated as acceptable to
  lose). Putting the registry in that same store would force every deployment's
  storage choice to also satisfy "can we ever afford to lose this," which is a
  materially different requirement than the one that choice is
  made against today.
- **Bootstrap.** Something still has to seed the store on first start, which means the
  file-based path doesn't disappear -- either it remains as the bootstrap source (so
  the store becomes a second representation that must stay in sync with it, not a
  replacement for it), or `credenza-manage` (or an admin UI) would need to become a
  complete editor for every `ClientRecord` field with no JSON-file escape hatch for
  anything it doesn't have a flag for yet -- a much larger surface than the
  read-modify-write-and-validate approach in Section 3.2.

A store-backed registry would only earn those costs if the actual goal were
multi-instance/HA config propagation in production -- the one limitation the
file+mtime design in Section 3.5 explicitly accepts (each worker/instance converges
independently, not atomically across a fleet). That is a materially different problem
from standalone/CI credential provisioning, is out of scope for this ADR, and would
warrant its own design if it becomes a real requirement.

---

## 5. Security Considerations

### 5.1 Registry File Is Trusted Configuration

`client_registry.json` is already trusted, admin-controlled configuration -- the same
file that defines every other registered client, including production ones. Nothing
about this ADR changes that trust model; it only adds a CLI for editing it, usable for
any client, not only disposable test ones. A standalone/dev/CI deployment should keep
its own registry file scoped to that deployment, not merged into a production
registry.

### 5.2 Secrets at Rest and in Transit

Consistent with existing `client_secret` adapter handling: only bcrypt hashes are
persisted, plaintext is displayed once and never re-derivable from the stored hash. The
`mint` subcommand accepts a secret via `--secret-file`, inline `--secret`, or an
interactive `getpass` prompt -- inline `--secret` is documented as leaking into shell
history and is provided for scripted CI use where that risk is already accepted (e.g. a
secret injected from a CI secret store into an ephemeral shell).

### 5.3 No New Runtime Surface

Because this is a client-side/config-editing tool and a real HTTP client of the
existing `client_credentials` grant, it introduces no new endpoint, no new
authentication path, and no new fail-open/fail-closed decision inside the running
Credenza server. The security posture of a deployment is unaffected by whether
`credenza-manage` exists; it is affected only by which clients an operator chooses to
add to `client_registry.json`, exactly as today. Installing it via `script-files`
(Section 3.1) changes nothing about that boundary -- it only puts the same script on
`PATH` instead of requiring an explicit path to run it.

---

## 6. Implementation Sketch

Affected files:

- `bin/credenza-manage` -- new script (see Section 3 for subcommands)
- `pyproject.toml` -- add `[tool.setuptools] script-files = ["bin/credenza-manage"]`
- `credenza/rest/helpers.py` -- new `get_client_registry(app)` accessor (Section 3.5)
- `credenza/rest/token.py`, `authorize.py`, `introspect.py`, `device.py`,
  `consent.py`, `login.py` -- swap the 9 direct `current_app.config["CLIENT_REGISTRY"]`
  reads for `get_client_registry(current_app)`
- `config/credenza.sample.json` -- document `CLIENT_REGISTRY_RELOAD_INTERVAL` (default
  `0`)

New dependencies: none (`bcrypt` and `requests` are already core dependencies).

### 6.1 End-to-End Verification

Against a local dev Credenza instance (`ENABLE_LEGACY_API=True`, memory/sqlite
backend, `CLIENT_REGISTRY_RELOAD_INTERVAL=1`):

1. `credenza-manage add-client test-admin --claims '{"roles":["admin"]}'` -- capture
   the printed secret.
2. Wait at least 1 second (Section 3.5), then `credenza-manage mint test-admin
   localhost:PORT --secret <secret>` -- confirm the token prints to stdout; repeat
   with `--deriva-cred alice.cred` and separately with `--cookiejar alice.jar`,
   inspecting each file against its expected shape.
3. A plain `curl -b alice.jar`/`requests` call to `PUT
   /session?resource=urn:deriva:rest:service:all` confirms the legacy
   `client`/`attributes` response shows `roles: ["admin"]` -- indistinguishable in
   shape from a real login.
4. `credenza-manage del-client test-admin`; wait 1 second; confirm the same
   `curl`/`requests` call now fails for that persona, and that `list` no longer shows
   it and the file still loads cleanly through `load_client_registry()`.
5. With `CLIENT_REGISTRY_RELOAD_INTERVAL=0` (default), repeat step 1 and confirm `mint`
   fails until the server is restarted -- confirms the opt-in default-off behavior is
   unchanged from today.
6. After `pip install -e .`, confirm `credenza-manage` is on `PATH` and runnable
   without an explicit `bin/` path prefix.

### 6.2 Unit Test Coverage

`credenza-manage` writes to `client_registry.json` (an operator may not immediately
double-check) and performs security-relevant operations (secret hashing,
validation-gated writes), so its JSON-manipulation and hashing logic gets unit test
coverage (e.g. `test/test_credenza_manage.py`) despite living outside the `credenza`
package's normal import path.