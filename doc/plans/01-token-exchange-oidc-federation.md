# Plan: OIDC Federated Token Support for Token Exchange API

The `/token` endpoint authenticates clients via `client_assertion` JWTs signed with their registered JWKS (`iss == sub == clientId`). This plan extends it to accept assertions signed by external OIDC issuers (notably K8s cluster API servers via projected service-account tokens), mapped to registered clients via a `(federated_issuer, federated_subject)` identity declared in the registrar's software statement.

The happy path is implemented. Remaining work is registrar-side trust-boundary hardening, negative tests, startup validation, observability, docs, and a type-level defense-in-depth pass. Each section below is tagged ✅ shipped or 🚧 remaining.

## Goals

- **Close the registrar trust boundary.** A compromised registrar in cluster A must not be able to register a client declaring a `federatedIdentity` pointing at cluster B's issuer. Mirrors the existing `allowedClusterName` constraint on `appId`.
- **Fail fast on misconfig.** Boot aborts on issuer collisions with tokendings' own `issuerUrl`, missing `federatedAssertionAudience`, out-of-range lifetimes, or unreachable `jwks_uri`.
- **Prove invariants with tests.** An impersonation guard plus a negative matrix.
- **Observable in production.** Auth-path metrics, JWKS fetch health, replay-evidence counter, alerts on regression and JWKS errors.

## Non-goals

- **Registration-time invariant "exactly one auth method per client."** Phased migration is accepted instead: clients may have both `jwks` and `federatedIdentity` during transition; revocation semantics documented per-path.
- **Full replay cache for federated assertions.** Drive by the `federated_jti_duplicate_observations` metric first; promote only if evidence warrants or threat modeling requires it pre-prod.
- **Merging the two claims verifiers.** Protocol requirements genuinely differ. See `02-auth-infra-unification.md` bundled cleanup B1 for the shared primitive.

## Design

### 1. ✅ Auth-path dispatch via `iss` claim

Self-signed assertions use `iss == clientId` (namespace strings like `dev-gcp:myteam:myapp`); federated issuers are URLs (e.g., K8s cluster API servers). Structurally disjoint — no collision possible. A forged `iss` still fails signature verification against the provider's JWKS, so the dispatch itself carries no trust.

Why not `client_assertion_type` / `client_id` param / Bearer header: all require client-side changes. `iss` sniffing requires none — the tokendings-native `client_assertion` envelope stays identical in both paths.

### 2. ✅ Registrar owns the identity mapping

Federated identity mapping (issuer + subject → Nais client) is the **registrar's** responsibility, expressed in the signed software statement. Tokendings only maintains a whitelist of allowed issuers and fetches their JWKS. Adding providers or changing mappings requires no tokendings config change — only a new software statement from the registrar.

This inverts the alternative ("tokendings holds per-provider cluster mappings") and keeps the issuer whitelist small, stable, and orthogonal to client churn.

### 3. ✅ Federated claims verifier

`FederatedClientAssertionJwtClaimsVerifier` — separate from `ClientAssertionJwtClaimsVerifier` because requirements genuinely differ:

- `iss` must equal a whitelisted federated issuer.
- `sub` present and non-empty.
- `aud` **contains** the configured `federatedAssertionAudience` (not `aud.size == 1` — RFC 7523 allows multi-value, and K8s SA tokens typically carry several audiences).
- `exp`, `iat` valid; lifetime bounded by `federatedAssertionMaxLifetime` (default 600s to accommodate K8s SA tokens, which have a 600s minimum — separate from the 120s `clientAssertionMaxExpiry` for self-signed).
- Required claims: `iss, sub, aud, exp, iat`. **Not** required: `jti`, `nbf` (K8s projected tokens often omit `jti`).

### 4. ✅ Nimbus `JWKSource` on the federated path

Federated issuer JWKS uses Nimbus `JWKSourceBuilder` via `CacheProperties`: `outageTolerantForever` + refresh-ahead + retrying. auth0's `JwkProviderBuilder.cached(...)` does **not** serve stale on upstream failure; a JWKS blip would break federated auth until recovery. `AuthProvider` (registration bearer-auth) still uses auth0 — refactor is `02-auth-infra-unification.md`.

### 5. ✅ Columns-authoritative federated identity

`OAuth2Client` stores `FederatedIdentity?`. Persistence uses dedicated indexed columns `federated_issuer` + `federated_subject` with a **partial unique index** `WHERE both IS NOT NULL`. `findByFederatedIdentity(iss, sub)` queries those columns directly.

Chose columns-authoritative over JSONB-with-trigger: simpler semantics, DB-enforceable uniqueness, no trigger to maintain. `@JsonInclude(NON_NULL)` on `OAuth2Client` prevents legacy rows flipping on first touch after deploy.

### 6. 🚧 Registrar-side: software statement carries federated identity

`ClientRegistration.kt`: add optional `federatedIssuer: String?` and `federatedSubject: String?` to `SoftwareStatement`; include in `verifySoftwareStatement()` as optional claims.

`ClientRegistrationApi.kt`: re-order validation. Currently `request.validate()` rejects empty JWKS *before* the software statement is parsed. Move the JWKS check to **after** `verifySoftwareStatement()` and enforce the real invariant: at least one of non-empty JWKS or federated identity. **Behaviour change**: malformed requests now get the software statement evaluated before being rejected for empty JWKS — note in release notes.

After verification, read `federatedIssuer`/`federatedSubject`, validate the issuer is in the whitelist, persist on the `OAuth2Client`.

### 7. 🚧 Registrar-to-issuer trust boundary

Extend `AuthProvider` with `allowedFederatedIssuers: Set<String>?` (nullable = allow all whitelisted issuers for this registrar). Enforced during registration: the calling registrar must be permitted to declare the given `federatedIssuer`. Without this, a compromised registrar in cluster A could register a client with a `federatedIdentity` pointing to cluster B's K8s issuer + a victim subject.

### 8. 🚧 Startup validation

`AppConfiguration` construction already fetches `.well-known` eagerly via `runBlocking` + `retryingHttpClient` (pre-Ktor; no event loop to block — idiomatic). Extend with:

- If any federated issuers configured, `federatedAssertionAudience` must be non-blank.
- No federated issuer URL may equal tokendings' own `issuerUrl` or collide with another whitelisted issuer (keeps `iss`-dispatch unambiguous).
- `maxAssertionLifetimeSeconds` in `1..3600`.
- Probe each issuer's `jwks_uri` (not just `.well-known` parse). _Subsumed by `02-auth-infra-unification.md` — drop if 02 lands first._
- Log resolved federated-issuer config at INFO (issuer, `jwks_uri`, audience, max lifetime).

### 9. 🚧 Impersonation-guard test

`TokenExchangeApiTest`: federated assertion with `sub == someVictimClientId` (a legacy self-signed client's id) must return `invalid_client`, not authenticate as the victim. Locks in the dispatch invariant cheaply once §6–§7 land.

### 10. 🚧 Negative federated test matrix

`TokenExchangeApiTest`: wrong `aud`, expired assertion, unknown issuer (not whitelisted), unregistered `(iss, sub)`, federated-identity mismatch between JWT and stored client, lifetime exceeded.

### 11. 🚧 Observability

- Metric: `client_auth_path{path=self_signed|federated, outcome=success|failure}`.
- Metric: `federated_jwks_fetch_latency{issuer}` + error counter.
- Metric: `federated_jti_duplicate_observations` — duplicate `jti` within assertion lifetime; evidence for replay-cache decision.
- Log fields: `federated_iss`, `federated_sub` alongside `client_id` on federated path.
- Span attribute: `auth.path` on `authenticateClient`.
- Alerts: self-signed success-rate drop post-deploy (regression canary); elevated JWKS fetch errors per issuer (upstream outage).

### 12. 🚧 Type-level defense-in-depth

Make the federated subject a distinct type inside `FederatedIdentity`, e.g. `value class FederatedSubject(val value: String)`, so it cannot flow into a `ClientId` slot. Wire format unchanged. **Cost**: `value class` interacts non-trivially with Jackson (explicit serialization config), nullable handling, collection boxing — budget a call-site audit, not a one-liner.

### 13. 🚧 Client-team docs

K8s projected-SA-token audience must equal `federatedAssertionAudience`. No re-signing; forward the mounted token as-is in `client_assertion`. Document in operator-facing README.

## Implementation order (remaining)

1. §6 (registrar-side model + validation re-ordering) — unblocks §7, §9, §10.
2. §7 (trust-boundary constraint) — security-critical; lands with §6's tests extended.
3. §9 (impersonation guard) — cheapest proof that §6+§7 hold.
4. §10 (negative matrix) — broader coverage.
5. §8 (startup validation) — operability; parallelisable with §10.
6. §11 (observability) — before meaningful prod traffic.
7. §12, §13 (type defense, docs) — any time after §11.

## Risks

- **Validation-order behaviour change (§6)** is user-visible: malformed requests get different error ordering. Call out in release notes.
- **`value class` migration (§12)** is not as low-effort as first framed; Jackson interop can surprise. Pilot on one call site before the sweep.
- **Shared software-statement signing key across registrars** means registrars sharing a key share the trust boundary for declaring federated identities. `allowedFederatedIssuers` (§7) mitigates cross-cluster impersonation but not cross-registrar-within-same-cluster. Acceptable today; revisit if the registrar population grows.
- **Longer assertion lifetimes widen replay window.** 600s+ (K8s minimum) vs 120s (self-signed). §11's `federated_jti_duplicate_observations` is the evidence gate for whether to promote to a full replay cache.

## Locked-in test discoveries

- `MockOAuth2Server.issueToken(issuerId, subject, DefaultOAuth2TokenCallback(issuerId=..., subject=..., audience=listOf(...), expiry=<=600))` fully simulates a federated OIDC issuer. `iss` claim equals `issuerUrl(issuerId).toString()`. `DefaultOAuth2TokenCallback` defaults to 3600s expiry; federated tests must pass `expiry <= 600` to stay under `federatedAssertionMaxLifetime`.
- `TokenExchangeRequestAuthorizer.targetClients` is audience-keyed; the authenticated federated client doesn't need to be in that map — `clientFinder` falls back to `config.clientRegistry.findClient(clientId)`.
