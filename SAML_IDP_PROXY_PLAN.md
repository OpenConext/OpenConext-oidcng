# SAML-to-OpenID proxy mode for OIDC-NG

## Context
Today OIDC-NG is an OIDC OP facing RPs and a SAML SP facing EngineBlock (Spring Security `saml2-service-provider`, one `RelyingPartyRegistration` "oidcng", config in `oidc/.../secure/SecurityConfiguration.java`).
New use-case: institutions migrate their IdP to an OpenID Provider. OIDC-NG must then act as a **SAML IdP towards EngineBlock** and an **OIDC RP towards the institution's OP**:

EB (SP) --AuthnRequest--> OIDC-NG --authz request--> institution OP --code--> OIDC-NG --token + userinfo--> OP --SAML Response (POST)--> EB ACS

This is the existing flow mirrored. Only generic plumbing (Mongo, TTL stores, key loading, Manage push, tests) can be reused; no SAML IdP code exists in oidcng.

## Findings that shape the design
- **openconext-saml-java** (`org.openconext:saml-idp:3.1.2`, OpenSAML 5.2.3, Java 21, servlet-API provided, no Spring dependency) already does the IdP side: `parseAuthnRequest` (hardened parser, issuer lookup, ACS check, embedded XML signature check, wrapping tests), `sendResponse` (signed Assertion+Response, auto-POST form, RelayState), IdP `metaData`. It fits our Spring Boot 4 / Tomcat 11 stack.
- Gaps in the library:
  1. No **HTTP-Redirect signature validation** (SigAlg/Signature query params). EB normally sends redirect-binding AuthnRequests, so this is mandatory.
  2. Only SUCCESS / NO_AUTHN_CONTEXT statuses; no general error mapping (e.g. AuthnFailed, RequestDenied).
  3. One IdP identity per `DefaultSAMLService`, SP list fixed at construction, metadata fetched at startup. No replay protection, no Destination/IssueInstant checks, ignores ForceAuthn/IsPassive/RequestedAuthnContext, NameID always persistent, IdP metadata only advertises POST SSO binding. No assertion encryption.
- Spring Security saml2 and the library both use OpenSAML 5; confirm the versions line up (spike item).
- OIDC RP side: Nimbus JOSE is already used in `TokenGenerator`. Add Nimbus `oauth2-oidc-sdk` (discovery, PKCE, code exchange, ID token validation, JWKS caching), or Spring Security `oauth2-client` with a dynamic `ClientRegistrationRepository`. Recommend Nimbus SDK: less coupling to the existing saml2 login chain. Verify whether it is already on the classpath.

## Design
**Multi-tenancy.** Each institution = one virtual IdP in EB: own entityID and SSO URL, e.g. `/saml/idp/{opId}/sso`, metadata at `/saml/idp/{opId}/metadata`. Build one `DefaultSAMLService` per institution (shared OIDC-NG signing key, SP list = EB only), cached and rebuilt when config changes.

**New package `oidc/proxy`** (kept apart from `oidc/saml`, `oidc/endpoints`):
- `SamlIdpEndpoint`: SSO (GET redirect + POST), metadata. Parses request via saml-idp, validates redirect signature, stores state, redirects to OP.
- `OpClientRegistry` / model `OpenIDProvider` (Mongo `@Document`): institution id, SAML entityID, issuer (discovery) or explicit endpoints, client_id, auth method (client_secret_basic or private_key_jwt), scopes, claim→SAML attribute mapping, NameID source, schacHomeOrganization, enabled flag. Load via Manage push like `manage/MetadataController` (new entity type) with an admin API fallback.
- `OpAuthenticationService`: builds authz request (`state`, `nonce`, PKCE S256; ForceAuthn→`prompt=login`, IsPassive→`prompt=none`, RequestedAuthnContext→`acr_values`, max_age), handles callback, token exchange, ID token validation (iss, aud, nonce, exp, sig via cached JWKS), userinfo call, checks userinfo `sub` == ID token `sub`.
- `OpCallbackEndpoint`: `/saml/idp/callback` (redirect_uri registered at the OPs).
- `ProxyRequestRepository` (Mongo, TTL like `SamlAuthenticationRequest`): SAML request ID, RelayState, ACS, institution, state, nonce, PKCE verifier. Lookup by `state`, single use, no dependence on session cookie (same rationale as `MongoSaml2AuthenticationRequestRepository`).
- `ClaimsToSamlMapper`: configurable mapping (modelled on `ResponseAuthenticationConverter` + `saml_mapping.json`, reversed) to a `List<SAMLAttribute>`; NameID = persistent derived from issuer+sub.
- Error mapping: OP error / denial / timeout → SAML Response with non-success status back to EB.

**Security config.** New filter chain (`@Order` before existing) matching `/saml/idp/**`, public, CSRF off for the SSO POST, rate/size limits. Must not interfere with the existing `/oidc/**`, `/saml2/**`, `/login/**` chain or the "oidcng" registration ID assumptions.

**Library work** (upstream in openconext-saml-java, release 3.2.0, preferred over forking in oidcng): redirect-binding signature validation; extra response statuses; Destination/IssueInstant checks; optional multiple EB signing certs; configurable NameID format. Assertion encryption only if EB requires it (assume no for MVP).

**Open assumptions** (confirm before building): EB sends signed redirect-binding requests; Manage gets a new entity type for these IdPs (separate team/work); one shared OIDC-NG signing certificate for all virtual IdPs is acceptable to EB; MVP supports authorization-code + PKCE only; no SLO.

## Effort estimate (one experienced developer)
| Phase | Work | Estimate |
|---|---|---|
| 0 | Spike: library + OpenSAML/Spring versions, EB binding/signature behaviour, OP sandbox, decide SDK | 3 d |
| 1 | saml-java upstream changes (redirect sig, statuses, checks) + release | 1 wk |
| 2 | SAML IdP endpoint, per-institution service cache, metadata | 1 wk |
| 3 | OIDC RP: registry/model, discovery, authz request, callback, token/userinfo, validation | 1.5 wk |
| 4 | Claims→SAML mapping, NameID, error mapping | 1 wk |
| 5 | Manage integration/admin API, config, Mongo changelog | 0.5-1 wk |
| 6 | Tests: unit, integration (mock OP via WireMock/mock-oauth2-server, signed EB requests), security (wrapping, replay, state/nonce) | 1.5 wk |
| 7 | Docs, EB-side config, pilot with one institution, fixes | 1 wk |

**Total ≈ 7-9 dev-weeks, i.e. ~2 months for one developer, ~5-6 calendar weeks for two** (working MVP after phases 0-4 + basic tests ≈ 5 weeks). Main risks: EB/Manage changes owned by other teams, variance between institutions' OPs (claims, ACR, auth methods) which drives pilot effort, and attribute/NameID semantics expected by SPs (e.g. stable persistent IDs, schacHomeOrganization, scoped affiliation).

## Build in OIDC-NG vs. new component vs. existing open-source proxy

**Option A: extend OIDC-NG (recommended)**
- Pros: same ops/deploy/monitoring/Mongo/key handling; same team and release train; reuses TTL stores, Manage push, test harness, logging; EB already trusts OIDC-NG as the SURFconext "protocol gateway" (no new trust anchor); one place for pseudonymisation/attribute policy; smallest total effort (~7-9 wks).
- Cons: couples two unrelated roles in one app (bigger blast radius, a bug in the new IdP path can take down the OP); different Spring Security chain and `"oidcng"` registration-ID assumptions to keep isolated; Mongo/session coupling; dependency conflicts (OpenSAML version shared by Spring Security and saml-idp); app grows in scope and test time.
- Mitigation: strict package/filter-chain isolation (`oidc/proxy`), feature flag, separate Spring profile so it can be deployed as a second instance of the same artifact.

**Option B: brand-new component (Spring Boot, same libs)**
- Pros: clean separation, independent scaling/release/failure domain, no legacy constraints, can choose Nimbus SDK freely.
- Cons: duplicates infra (Mongo config, key mgmt, Manage integration, CI/CD, docker, monitoring, security hardening, logging); new service to operate and secure; same SAML/OIDC code must be written anyway, so only ~1-2 wks saved on coupling, ~2-3 wks added on scaffolding. Sensible only if the team wants to deploy it separately long term. Note: Option A with a separate deployment profile gets most of this benefit.

**Option C: existing open-source proxy**
- **SATOSA (IdentityPython, Python)**: purpose-built SAML2 frontend + OpenID Connect backend proxy; plugin model, micro-services for attribute mapping, a documented SAML2-to-OIDC setup. Pros: closest functional match, no protocol code to write. Cons: Python stack, new to this Java-based team/ops; multi-tenant dynamic institution onboarding via Manage push not built-in (config files / custom plugin); release cadence slow (latest release I found was 8.4.0, June 2023, verify current status); no integration with our Mongo/Manage/audit/log conventions; backend plugin per OP unless a dynamic backend is written.
- **Keycloak (Java)**: identity brokering with OIDC (and SAML) upstream providers and a SAML IdP towards clients. Pros: mature, maintained, admin UI, per-institution IdP config via admin REST API, discovery support. Cons: heavyweight; its model is realm/users/clients (brokered users are stored locally, which conflicts with a stateless pass-through proxy and privacy/pseudonymisation rules); one SAML IdP identity per realm (many institutions = many realms or a hacky setup); EB would need Keycloak endpoints/metadata per institution; attribute and NameID semantics need mappers; large operational footprint.
- **Apereo CAS (Java)**: SAML2 IdP with delegated authentication via pac4j to external SAML/OIDC providers. Pros: mature, SAML IdP features (encryption, SLO), multiple delegated providers. Cons: heavy overlay-based build, steep learning curve, OIDC delegation docs less clear (verify), same multi-tenancy/Manage questions.
- Others considered, not a fit: Dex (OIDC output only, no SAML IdP), SimpleSAMLphp/Shibboleth IdP (SAML IdP, but OIDC upstream is via add-on modules and not designed for hundreds of dynamic OPs).
- General cons of C: another product to patch and operate, config-driven rather than data-driven onboarding, and SURF-specific requirements (Manage metadata, eduID/pseudonymisation, collabPersonId semantics, audit) must be adapted.
- Quick PoC possible with SATOSA or Keycloak in ~3-5 days to validate institution OP behaviour, but not recommended as the production path.

**Recommendation:** A (extend OIDC-NG), isolated in `oidc/proxy` behind a profile/flag so it can run as a separate deployment later. Revisit only if there are many (>~50) institutions with highly divergent OP quirks, where SATOSA's micro-service plugins might pay off. Consider a 3-day SATOSA or Keycloak PoC as a throwaway reference to test OPs.

Sources: [SATOSA](https://github.com/IdentityPython/SATOSA), [Keycloak server admin docs](https://www.keycloak.org/docs/26.8.2/server_admin/), [Apereo CAS delegated authentication](https://apereo.github.io/cas/7.1.x/integration/Delegate-Authentication.html).

## Verification
- Unit: library tests (redirect signature valid/invalid, wrapping); ID token validation negatives (bad nonce/aud/iss/sig, replayed state, sub mismatch).
- Integration (extend `AbstractIntegrationTest` pattern, RestAssured + Mongo + WireMock/mock OP): signed AuthnRequest → redirect to OP → callback → decode and verify the signed SAML Response (InResponseTo, audience, attributes, NameID).
- Manual end-to-end in the docker dev setup: EB dev → OIDC-NG → a test OP (e.g. Keycloak/mock-oauth2-server).
- Regression: existing OP-mode tests must stay green (`mvn test` in `oidc/`).
