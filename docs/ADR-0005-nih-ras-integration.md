# ADR-0005: NIH Research Authorization Service (RAS) Integration

## 1. Status

**Proposed**
Decision Date: 2026-03-12

### Review History

| Date       | Status   | Notes         |
|------------|----------|---------------|
| 2026-03-12 | Proposed | Initial draft |

---

## 2. Context

NIH's Research Authorization Service (RAS) is an OIDC-based identity and
access management system for controlled-access biomedical data. It implements
the GA4GH Passport specification (v1.2), issuing cryptographically signed
Passports containing Visas that assert access rights to controlled datasets
(primarily dbGaP studies), researcher status, institutional affiliations,
and data use agreement acceptance.

Deployments serving NIH-affiliated users or controlled-access biomedical
data require NIH Login as a supported identity provider and, where applicable,
the ability to consume RAS-issued access grants. Credenza, as the OIDC
Relying Party and session broker, is the natural integration point for RAS.

The integration has two distinct components:

1. **OIDC Relying Party configuration**: add NIH-RAS as a named realm in
   `oidc_idp_profiles.json`, allowing users to authenticate via NIH Login.

2. **Session augmentation**: after authentication, extract and validate the
   GA4GH Passport and Visas issued by RAS, and populate canonical session
   claims that resource servers can use for access control decisions.

### 2.1 GA4GH Passport and Visa Model

A GA4GH Passport is returned from the OIDC userinfo endpoint (when the
`ga4gh_passport_v1` scope is requested) as an array of signed Visa JWTs
stored in the `ga4gh_passport_v1` claim. Per the GA4GH AAI OIDC Profile,
GA4GH claims MUST NOT appear in ID tokens -- the passport is only available
via the `/userinfo` endpoint, not the token response.

Each Visa is an independently signed JWT with:

- A `typ: "vnd.ga4gh.visa+jwt"` header and a `jku` (JWKS URL) for
  signature verification.
- A `ga4gh_visa_v1` payload claim containing:
  - `type`: the visa type (see below)
  - `value`: the assertion value (often a URI or structured identifier)
  - `source`: the asserting authority
  - `by`: who made the assertion (`self`, `peer`, `system`, `so`, `dac`)
  - `asserted`: Unix timestamp of when the assertion was made
  - (Visa expiry is the JWT `exp` claim, not a field inside `ga4gh_visa_v1`)

Visa types defined by GA4GH and issued by RAS:

| Type                              | Source    | Description                                               |
|-----------------------------------|-----------|-----------------------------------------------------------|
| `ControlledAccessGrants`          | GA4GH     | Access to a specific controlled dataset (generic)         |
| `AffiliationAndRole`              | GA4GH     | Institutional affiliation (e.g., eRA Commons role)        |
| `AcceptedTermsAndPolicies`        | GA4GH     | User has accepted a data use agreement or policy          |
| `ResearcherStatus`                | GA4GH     | Verified researcher status (e.g., bona fide researcher)   |
| `LinkedIdentities`                | GA4GH     | Links to other identity systems (eRA Commons, NIH Login)  |
| `https://ras.nih.gov/visas/v1.1`  | RAS/dbGaP | Consolidated dbGaP access grants (RAS custom type)        |

For dbGaP access control the RAS-specific custom visa type
`https://ras.nih.gov/visas/v1.1` is the primary mechanism. Rather than
one `ControlledAccessGrants` visa per dataset, RAS consolidates all of a
user's dbGaP access authorizations into a single visa whose `value` field
contains a `ras_dbgap_permissions` array. Each entry in that array
identifies one study by `phs_id`, `version`, `participant_set`,
`consent_group`, and `role`.

### 2.2 Existing Augmentation Infrastructure

Credenza already provides a `SessionAugmentationProvider` base class with
three extension points:

- `fetch_dependent_tokens(access_token, userinfo, ...)`: obtain additional
  tokens from the IDP (used by the Globus provider for dependent tokens).
- `process_additional_tokens(tokens, ...)`: post-process token responses.
- `enrich_userinfo(userinfo, additional_tokens)`: add claims to the session.

The `GlobusSessionAugmentationProvider` is the reference implementation,
demonstrating the pattern for IDP-specific augmentation. The RAS provider
will follow the same pattern.

The `session_augmentation_provider` key in `oidc_idp_profiles.json` activates
a named provider class for a given realm, passing it the OIDC access token
and initial userinfo after login.

---

## 3. Decision

Credenza SHALL integrate NIH-RAS as a supported OIDC realm by:

1. Adding a `nih-ras` realm configuration to `oidc_idp_profiles.json`.
2. Implementing a `RasSessionAugmentationProvider` that extracts and validates
   GA4GH Passport Visas and populates canonical session claims.
3. Defining a canonical claim namespace (`ras_*`) for RAS-derived attributes
   stored in `session.userinfo`.

Visa signature verification SHALL be mandatory. Expired visas SHALL be
excluded from session claims. Untrusted visa issuers SHALL be rejected.

---

## 4. Architecture

### 4.1 OIDC Realm Profile

Add to `oidc_idp_profiles.json`:

```json
"nih-ras": {
  "discovery_url": "https://sts.nih.gov/.well-known/openid-configuration",
  "scopes": "openid email profile ga4gh_passport_v1",
  "client_secret_file": "secrets/nih_ras_client_secret.json",
  "session_augmentation_provider":
    "credenza.api.session.augmentation.ras_provider:RasSessionAugmentationProvider",
  "trusted_visa_issuers": [
    "https://sts.nih.gov"
  ]
}
```

Notes:
- `ga4gh_passport_v1` is the scope that causes RAS to include the passport
  in the userinfo response.
- `trusted_visa_issuers` is a profile-level allowlist of visa issuers
  whose signatures will be verified and whose visas will be accepted.
  Visas from issuers not in this list SHALL be skipped, not rejected
  (the passport may contain visas from multiple brokers; only trusted ones
  are processed).
- Endpoint URLs above are indicative; operators MUST verify current NIH-RAS
  production and staging endpoints against NIH's official documentation
  before deployment. NIH provides separate staging (`stsstg.nih.gov`) and
  production environments; the profile should be environment-specific.

### 4.2 RasSessionAugmentationProvider

A new file `credenza/api/session/augmentation/ras_provider.py`:

```python
class RasSessionAugmentationProvider(DefaultSessionAugmentationProvider):
    ...
```

**`enrich_userinfo(userinfo, additional_tokens)`**:

This is the primary extension point. Called after OIDC login with the
initial userinfo dict (which includes `ga4gh_passport_v1` from RAS).

Logic:

1. Extract `ga4gh_passport_v1` from `userinfo`. If absent, log a warning
   and return False (non-fatal; user authenticated but no passport).
2. Load `trusted_visa_issuers` from the realm profile configuration.
3. For each Visa JWT in the passport array:
   a. Decode the JWT header to extract `jku` (JWKS URL) and `kid`.
   b. If the JWT `iss` is not in `trusted_visa_issuers`, skip.
   c. If the `jku` domain does not match the issuer's domain, skip and log
      (SSRF mitigation -- see section 4.5).
   d. Fetch the issuer's JWKS (with caching) from the `jku` URL.
   e. Verify the JWT signature.
   f. Verify the JWT `exp` has not passed.
   g. Parse the `ga4gh_visa_v1` claim.
   h. Dispatch to the appropriate handler by `type`.
4. Populate canonical claims into `userinfo` (see section 4.3).
5. Store the passport metadata in `userinfo["ras_passport_meta"]`
   (expiry summary, issuer, processed count) for audit and TTL tracking.
6. Return True if any visas were successfully processed.

**`fetch_dependent_tokens`**: returns `{}` (no dependent token flow for RAS).

**`process_additional_tokens`**: delegates to `DefaultSessionAugmentationProvider`.

### 4.3 Canonical Claim Mapping

RAS-derived claims are stored as flat top-level keys in `session.userinfo`
under a `ras_` naming prefix. All claim names are top-level members
consistent with ADR-0001 §5.7 and RFC 7662 -- there is no nested `ras`
container object. Values may be lists or scalars; list items may be
structured objects, consistent with standard OIDC practice (e.g., `groups`).

| Canonical Claim                  | Source Visa Type                    | Value type                                        |
|----------------------------------|-------------------------------------|---------------------------------------------------|
| `ras_dbgap_permissions`          | `https://ras.nih.gov/visas/v1.1`    | List of dbGaP permission objects (see below)      |
| `ras_controlled_access_grants`   | `ControlledAccessGrants`            | List of generic access grant objects              |
| `ras_affiliation_and_role`       | `AffiliationAndRole`                | List of affiliation strings                       |
| `ras_accepted_terms`             | `AcceptedTermsAndPolicies`          | List of accepted policy URIs (strings)            |
| `ras_researcher_status`          | `ResearcherStatus`                  | List of researcher status strings                 |
| `ras_linked_identities`          | `LinkedIdentities`                  | List of linked identity strings                   |
| `ras_passport_earliest_exp`      | (metadata)                          | Integer Unix timestamp; minimum visa expiry       |
| `ras_passport_processed_at`      | (metadata)                          | Integer Unix timestamp; augmentation time         |
| `ras_passport_visa_count`        | (metadata)                          | Integer; number of successfully processed visas   |

Each `ras_dbgap_permissions` entry (from the RAS custom visa):

```json
{
  "phs_id": "phs000001",
  "version": "v1",
  "participant_set": "p1",
  "consent_group": "c1",
  "consent_name": "General Research Use",
  "role": "applicant",
  "expires": 1577836800
}
```

`expires` is carried from the parent Visa JWT `exp` into each permission entry
so resource servers can check currency without re-parsing JWTs. Resource
servers enforcing dbGaP access SHOULD use `ras_dbgap_permissions` and check
`phs_id` and `expires` for each required study.

Each `ras_controlled_access_grants` entry (from standard GA4GH visas, if present):

```json
{
  "value": "https://dbgap.ncbi.nlm.nih.gov/aa/wga.cgi?...phs000001",
  "source": "https://dbgap.ncbi.nlm.nih.gov/...",
  "by": "dac",
  "asserted": 1546300800,
  "expires": 1577836800
}
```

### 4.4 Visa Expiry and Session TTL

Visas have their own independent expiry (`exp` claim in each Visa JWT),
which may be shorter or longer than the Credenza session TTL. Three cases:

1. **Visa expires before session**: the session remains valid but the
   controlled-access grant in `ras_controlled_access_grants` is stale.
   Resource servers MUST check `expires` in the grant claim rather than
   relying solely on session validity.

2. **Session expires before all visas**: normal case; the session lifecycle
   governs access.

3. **Passport refresh**: RAS does NOT issue refresh tokens; sessions
   established via NIH-RAS are fixed-lifetime with no upstream token
   refresh. The device flow's background refresh mechanism does not apply
   to RAS sessions. When a RAS session expires, the user must re-authenticate
   to obtain a fresh passport.

The `ras_passport_earliest_exp` claim stores the minimum visa expiry
across all processed visas. This can be used to bound the session TTL:
Credenza MAY configure the session `expires_at` to be the minimum of the
configured session TTL and `ras_passport_earliest_exp` for RAS sessions,
ensuring sessions do not outlive their most-restrictive visa. This is opt-in
via a `bound_session_ttl_to_visa_expiry` profile flag.

### 4.5 Security Considerations

**Visa signature verification is mandatory.** Passports returned from the
userinfo endpoint are already transport-secured by HTTPS, but individual
Visa JWTs carry their own signatures because they may be passed between
systems independently. Skipping signature verification would allow forged
access grants.

**JWKS fetch and SSRF mitigation.** Each Visa JWT contains a `jku` header
with the JWKS URL for that visa's issuer. The provider MUST validate that:
- The `jku` URL's domain matches the expected domain of the visa `iss`.
- The `jku` URL uses HTTPS.
- The `jku` URL is in (or derived from) the `trusted_visa_issuers` list.

This prevents a malicious passport from directing Credenza to fetch JWKS
from an attacker-controlled endpoint.

**Trusted issuer allowlist.** Only issuers explicitly listed in
`trusted_visa_issuers` SHALL have their visas processed. Visas from unknown
issuers are silently skipped and logged. This is important because the
GA4GH Passport spec allows multi-party passports where visas come from
different brokers; Credenza should only trust those it has been configured
to trust.

**Algorithm restriction.** RAS signs visa JWTs using RS256 exclusively.
The provider SHALL enforce an algorithm allowlist and reject visas signed
with `none` or any symmetric algorithm regardless of what the JWT header
specifies. The allowlist should be configurable to accommodate future
algorithm additions (GA4GH v1.2 permits ES256) but default to RS256 for RAS.

**JWKS caching.** The same caching approach as ADR-0004 applies: cache JWKS
by issuer URL with a configurable TTL (default: 3600s). Failed fetches
SHOULD cause the visa to be skipped (not accepted without verification),
and MUST be logged.

**Visa array poisoning.** If the `ga4gh_passport_v1` array contains a visa
that fails validation (bad signature, wrong issuer, malformed), the provider
SHALL skip that visa, log the failure, and continue processing remaining
visas. A single invalid visa SHALL NOT invalidate the entire passport or
abort the session.

**Sensitive claim handling.** `ras_controlled_access_grants` contains
information about which controlled biomedical datasets a user can access.
This is sensitive. Credenza's session encryption (AES-GCM at rest) applies
to all session data. The introspection endpoint's resource server gating
(Option B, ADR-0001) ensures only authorized resource servers can retrieve
these claims.

### 4.6 Passport Endpoint vs Userinfo

RAS may expose passports via:
- The standard OIDC userinfo endpoint (when `ga4gh_passport_v1` scope is
  requested) -- the primary path.
- A separate passport endpoint.

The augmentation provider SHOULD first check `userinfo["ga4gh_passport_v1"]`
as populated by the standard OIDC flow. If absent and a `passport_endpoint`
is configured in the realm profile, the provider MAY fetch directly from
that endpoint using the OIDC access token as a bearer token. The separate
endpoint path is a fallback for IDP configurations that do not embed the
passport in the userinfo response.

### 4.7 Claim Mapper Integration

The existing `claim_mapper.py` is the canonical normalization layer for
all session claims. RAS canonical claim names (`ras_*`) SHALL be registered
in the claim mapper configuration so that they survive the standard
normalization pipeline and are not unexpectedly renamed or dropped.

The `IDP_CLAIM_MAPS` configuration entry for the `nih-ras` realm should
preserve `ga4gh_passport_v1` (needed by the augmentation provider) and
passthrough `ras_*` claims written by the provider without modification.

### 4.8 Sample Profile Configuration

Staging (for testing):

```json
"nih-ras-staging": {
  "discovery_url": "https://stsstg.nih.gov/.well-known/openid-configuration",
  "scopes": "openid email profile ga4gh_passport_v1",
  "client_secret_file": "secrets/nih_ras_staging_client_secret.json",
  "session_augmentation_provider":
    "credenza.api.session.augmentation.ras_provider:RasSessionAugmentationProvider",
  "trusted_visa_issuers": ["https://stsstg.nih.gov"],
  "bound_session_ttl_to_visa_expiry": false
}
```

Production:

```json
"nih-ras": {
  "discovery_url": "https://sts.nih.gov/.well-known/openid-configuration",
  "scopes": "openid email profile ga4gh_passport_v1",
  "client_secret_file": "secrets/nih_ras_client_secret.json",
  "session_augmentation_provider":
    "credenza.api.session.augmentation.ras_provider:RasSessionAugmentationProvider",
  "trusted_visa_issuers": ["https://sts.nih.gov"],
  "bound_session_ttl_to_visa_expiry": true
}
```

---

## 5. Resource Server Integration

Resource servers consuming Credenza tokens (via introspection) that need
to enforce controlled-access dataset permissions SHOULD:

1. Check `ras_dbgap_permissions` for dbGaP study access (RAS custom visa).
   For each entry, verify `phs_id` matches the required study and `expires`
   has not passed. `expires` is the definitive currency check -- sessions
   can outlive individual visa grants.
2. Check `ras_controlled_access_grants` for resources using the standard
   GA4GH `ControlledAccessGrants` visa type. Verify `value` matches the
   required resource and `expires` has not passed.
3. Check `ras_affiliation_and_role` or `ras_researcher_status` for
   attribute-based access policies if applicable.
4. Deny access if no matching unexpired grant or attribute is found.

This logic belongs in the resource server, not in Credenza. Credenza
surfaces the claims; enforcement is the resource server's responsibility
(consistent with ADR-0001 section 3.6).

---

## 6. Acceptance Criteria

1. `nih-ras` realm profile loads without error from `oidc_idp_profiles.json`.
2. OIDC login via NIH-RAS completes and produces a Credenza session.
3. `RasSessionAugmentationProvider.enrich_userinfo()` processes all supported
   visa types and populates `ras_*` claims in `session.userinfo`.
4. Visa signature verification is performed for each visa; invalid signatures
   cause the visa to be skipped, not the session to fail.
5. Expired visas are excluded from all `ras_*` claims.
6. Visas from issuers not in `trusted_visa_issuers` are skipped and logged.
7. `jku` domain is validated against the visa issuer domain before JWKS fetch.
8. JWKS is cached per issuer within the configured TTL.
9. `ras_passport_earliest_exp` reflects the minimum visa expiry across all processed visas.
10. When `bound_session_ttl_to_visa_expiry` is true, session `expires_at`
    is bounded by `ras_passport_earliest_exp`.
11. Introspection response includes `ras_*` claims for sessions with a RAS realm.
12. Tests cover: no passport in userinfo (graceful), single valid visa,
    mixed valid/expired visas, untrusted issuer visa skipped, bad signature
    skipped, JWKS fetch failure (visa skipped), `ControlledAccessGrants`
    and `AffiliationAndRole` claim mapping.

---

## 7. Consequences

### Positive

- Deployments can accept NIH credentials for controlled-access data.
- GA4GH Passport/Visa claims are surfaced to resource servers via introspection
  without requiring each resource server to implement passport parsing.
- Visa signature verification happens once at session creation time, not on
  every request.
- The augmentation provider pattern means RAS integration is fully isolated
  from the core Credenza flow -- it is opt-in per realm.

### Negative

- JWKS fetching at session creation introduces an outbound HTTP call to NIH
  endpoints. Network failures delay login (mitigated by caching and skip-on-failure).
- Visa expiry independent of session expiry creates a dual-TTL model that
  resource servers must understand. The `expires` field in grant claims
  makes this explicit but requires resource server awareness.
- RAS does not issue refresh tokens; sessions are fixed-lifetime. Users must
  re-authenticate when sessions expire, unlike Globus/device flow sessions
  that can auto-refresh.
- NIH-RAS staging and production are separate environments requiring separate
  client registrations and credentials.
- The GA4GH Passport spec is evolving (currently v1.2); the provider may need
  updates as the spec matures or RAS adds new visa types.

---

## 8. Alternatives Considered

### 8.1 Passport Forwarding Without Processing

Pass the raw `ga4gh_passport_v1` array through to session claims unmodified,
and let resource servers parse and validate visas themselves. Rejected because
it duplicates JWKS fetching and signature verification across every resource
server and exposes them to raw JWT handling complexity. Centralizing
verification in Credenza is a better separation of concerns.

### 8.2 Per-Request Passport Validation

Re-fetch and re-validate the passport on every introspection call rather than
at session creation. Rejected because it adds NIH endpoint dependency to the
hot path of every token validation. Session creation is the right time to
do the expensive work.

### 8.3 Separate RAS Session Type

Introduce a `SessionType.RAS` to distinguish RAS sessions from other user
sessions. Rejected -- the existing `SessionType.USER` with realm-specific
augmentation claims is sufficient. The realm name in the session already
identifies RAS sessions for audit and logging purposes.

---

## 9. Summary

NIH-RAS integration is implemented as an OIDC realm configuration plus
a session augmentation provider following the existing Globus provider
pattern. GA4GH Passport Visas are verified at session creation, and
their claims are normalized into a `ras_*` canonical namespace in
`session.userinfo`, making them available to resource servers via
introspection without further NIH endpoint dependencies on the request
hot path. Visa expiry is surfaced explicitly in claims so resource
servers can enforce currency independently of session validity.