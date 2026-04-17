# Plan: Unify Client Authentication Infrastructure

Three concerns in tokendings consume OIDC issuers and JWKS, each with its own plumbing:

| Concern | Where | JWKS source | Claims verifier |
|---|---|---|---|
| Registration bearer-token auth | `BearerTokenAuthenticationConfiguration.kt`, `AuthProvider` | **auth0** `JwkProvider` + `JwkProviderBuilder.cached(...)` | inline (`JWT.require(...).withIssuer(...).build()`) |
| Subject-token validation (`/token`) | `SubjectTokenIssuer`, `TokenValidator` | **Nimbus** `JWKSource` (via `CacheProperties`) | `DefaultJWTClaimsVerifier` |
| Federated client-assertion auth (`/token`) | `FederatedIssuer`, `TokenRequestContext.authenticateFederated` | **Nimbus** `JWKSource` (via `CacheProperties`) | `FederatedClientAssertionJwtClaimsVerifier` |

Eagerness is **half-done**: all three fetch `.well-known` at `AppConfiguration` construction via `runBlocking` + `retryingHttpClient` (`AppConfiguration.kt:90`, `:154`, `:199`), but **JWKS fetching is lazy** in every path — auth0's `JwkProviderBuilder.cached(...)` fetches on first `.get(kid)`, and Nimbus's `JWKSourceBuilder` with `refreshAheadCache` schedules a refresh but does not block boot on an initial fetch. A broken `jwks_uri` therefore surfaces as a first-request failure, not a boot failure.

Three real problems:

1. **Two JWKS stacks in one app.** auth0's `JwkProviderBuilder.cached(...)` does not serve stale on upstream failure; Nimbus's `JWKSourceBuilder` does (via `outageTolerantForever`, `refreshAheadCache`, `retrying`). Registration bearer-auth is the only path still on auth0 — and it's the path most sensitive to IdP outages (a blip breaks client registration).
2. **Same upstream IdP, three independent config entries.** A K8s cluster can act as (a) the OIDC provider for the registrar's own auth (`AUTH_PROVIDER_CONFIGS`), (b) a federated-client-assertion issuer (`FEDERATED_CLIENT_AUTH_ISSUERS`), and (c) potentially a subject-token issuer (`SUBJECT_TOKEN_ISSUERS`). Today each list fetches `.well-known` separately and builds its own JWKS cache. Three connection pools, three refresh schedules, three sources of drift.
3. **Lazy JWKS fetching hides boot-time misconfiguration.** A broken `jwks_uri` only surfaces when the first JWT arrives at the endpoint that needs it — which in federated / registration paths can be minutes or hours after deploy.

## Goals

- **Nimbus is the single JWKS source of truth.** auth0 `JwkProvider` survives only as a thin adapter where Ktor's DSL requires `com.auth0.jwt.interfaces.JWTVerifier`.
- **One issuer → one JWKS cache**, reusable across concerns. Registration bearer-auth and federated client-assertion for the same K8s cluster share one cache, one refresh schedule.
- **Eager, fail-fast boot.** `.well-known` resolution is already eager. Extend the same policy to JWKS: every configured issuer must have its `jwks_uri` fetched **and** at least one key loaded into the Nimbus cache before `AppConfiguration` construction returns. Any failure (unreachable `.well-known`, unreachable `jwks_uri`, empty JWKS, malformed JWK) throws and aborts startup. This subsumes federation-plan goal #4's "probe each issuer's `jwks_uri` at startup" bullet — once this refactor lands, that bullet can be dropped from the federation plan.

## Non-goals

- Unifying `ClientAssertionJwtClaimsVerifier` and `FederatedClientAssertionJwtClaimsVerifier`. Their protocol requirements genuinely differ (`aud` size, required claims, lifetime policy). Keep two concrete verifiers — but factor the shared primitives (see "Bundled cleanups" below).
- Changing `TokenValidator`'s `extraClaimsVerifier` hook — it already supports the reuse pattern the federation work needed.
- Merging `SubjectTokenIssuer` with the client-auth issuer registry. Subject tokens serve a different purpose (they're the input to token exchange, not the authenticator of the client); unifying would confuse the model.
- Making `AppConfiguration` construction suspendable. `runBlocking` at boot, before the Ktor server starts, is idiomatic — no event loop to block. Churn without benefit.
- Unifying the local `WellKnown` DTO (tokendings' own discovery doc, served outward) with Nimbus `OIDCProviderMetadata` (used to parse upstream IdPs). Different directions, different shapes.
- A single cross-cutting audience validator across bearer-auth, client-assertion, and `TokenValidator`. The three call sites enforce deliberately different audience semantics (containsAll of configured audiences; tokendings' own issuer URL; configured `federatedAssertionAudience`). A helper with enough flags to cover all three would be more confusing than the three inline checks.

## Design

### 1. Introduce `IssuerJwks` — the shared per-issuer cache

A single class owning `.well-known` + Nimbus `JWKSource` for one issuer, with boot-time JWKS warm-up:

```kotlin
data class IssuerJwks(
    val issuer: String,
    val jwksUri: String,
    val jwkSource: JWKSource<SecurityContext>,  // Nimbus
) {
    companion object {
        fun fromWellKnown(wellKnownUrl: String): IssuerJwks = runBlocking {
            val wk = retryingHttpClient.get(wellKnownUrl).body<WellKnown>()
            val jwkSource = CacheProperties(jwksURL = URL(wk.jwksUri)).jwkSource
            // Fail-fast: force an initial JWKS fetch. Nimbus's refresh-ahead cache
            // otherwise defers the first fetch until first JWT validation, which
            // masks misconfigured jwks_uri until traffic arrives.
            val keys = jwkSource.get(JWKSelector(JWKMatcher.Builder().build()), null)
            require(keys.isNotEmpty()) { "JWKS at ${wk.jwksUri} returned no keys" }
            log.info("Loaded ${keys.size} JWK(s) for issuer=${wk.issuer} from ${wk.jwksUri}")
            IssuerJwks(wk.issuer, wk.jwksUri, jwkSource)
        }
    }
}
```

- Collapses `AuthProvider`'s well-known fetch, `FederatedIssuer`'s well-known fetch, and `SubjectTokenIssuer`'s well-known fetch (three structurally identical blocks in `AppConfiguration.kt`) into one call site.
- `AppConfiguration` builds **one `Map<String, IssuerJwks>` keyed by discovered `iss`** from the union of all three env-var lists, deduplicated.
- `AuthProvider`, `FederatedIssuer`, `SubjectTokenIssuer` stop owning JWKS plumbing; they become thin records pointing at an `IssuerJwks` plus concern-specific policy (`allowedClusterName`, `allowedSubjects`, `audience`, `maxLifetimeSeconds`, subject-token mappings).

### 2. Nimbus → auth0 `JwkProvider` adapter (Ktor-only)

Ktor's `jwt { verifier { ... } }` DSL accepts a `com.auth0.jwt.interfaces.JWTVerifier`. The current code uses `auth0.JwkProvider.get(kid)` only to pull a `publicKey` + `algorithm` to build that `JWTVerifier` (`BearerTokenAuthenticationConfiguration.kt:89-103`). The auth0 surface actually used is tiny.

Adapter:

```kotlin
class NimbusJwkProviderAdapter(
    private val jwkSource: JWKSource<SecurityContext>,
) : com.auth0.jwk.JwkProvider {
    override fun get(keyId: String): com.auth0.jwk.Jwk {
        val matcher = JWKSelector(JWKMatcher.Builder().keyID(keyId).build())
        val jwk = jwkSource.get(matcher, null).firstOrNull()
            ?: throw JwkException("JWK not found for kid=$keyId")
        return Jwk.fromValues(jwk.toJSONObject())
    }
}
```

- Preserves `com.auth0.jwk.Jwk` semantics expected by `Jwk.makeAlgorithm()` (`BearerTokenAuthenticationConfiguration.kt:115-125`).
- `jwkSource.get(...)` transparently uses Nimbus's outage-tolerant, refresh-ahead cache.
- Drop `JwkProviderBuilder`, `CACHE_SIZE`, `EXPIRES_IN`, `BUCKET_SIZE` from `AppConfiguration`. Drop the `Accept`-header configuration (Nimbus handles content negotiation; confirm `AuthProviderAcceptHeaderTest` still passes — see Risks).

### 3. Refactor `AuthProvider`

Current:
```kotlin
class AuthProvider(val issuer: String, val jwkProvider: JwkProvider, ...)
```

After:
```kotlin
class AuthProvider(
    val issuerJwks: IssuerJwks,
    val allowedClusterName: String? = null,
    val allowedSubjects: Set<String>? = null,
) {
    val issuer: String get() = issuerJwks.issuer
    val jwkProvider: com.auth0.jwk.JwkProvider = NimbusJwkProviderAdapter(issuerJwks.jwkSource)
}
```

- `bearerTokenVerifier` needs no change — it still calls `provider.jwkProvider.get(kid)`.
- `fromWellKnown` and `fromSelfSigned` become thin constructors over `IssuerJwks` (`fromSelfSigned` can wrap a static `JWKSet` in an `ImmutableJWKSet` to stay on the Nimbus-only path).

### 4. Refactor `FederatedIssuer` and `SubjectTokenIssuer`

Both already use Nimbus `CacheProperties`. Replace their private `cacheProperties` with a reference to `IssuerJwks`:

```kotlin
class FederatedIssuer(val issuerJwks: IssuerJwks) {
    val issuer: String get() = issuerJwks.issuer
}

class SubjectTokenIssuer(val issuerJwks: IssuerJwks, val mappings: ...) {
    val issuer: String get() = issuerJwks.issuer
}
```

`TokenValidator` already accepts `JWKSource` directly (`TokenValidator.kt:24-28`). Update call sites to pass `issuerJwks.jwkSource` instead of `cacheProperties`.

### 5. Issuer registry in `AppConfiguration`

```kotlin
class AppConfiguration(...) {
    // Built once from the union of AUTH_*, FEDERATED_*, SUBJECT_TOKEN_* well-known URLs
    val issuers: Map<String, IssuerJwks>  // keyed by discovered `iss`

    val clientRegistrationAuthProperties: ClientRegistrationAuthProperties  // references issuers
    val federatedClientAuthProperties: FederatedClientAuthProperties        // references issuers
    // subject-token issuers likewise
}
```

Deduplication: if two env-var entries resolve to the same `iss`, `EnvConfiguration` fetches `.well-known` once, builds one `IssuerJwks`, and both concerns share it. Log at INFO which concerns each issuer serves, so operators see the reuse.

Collision with tokendings' own `issuerUrl` (startup footgun from federation plan goal #4) is now a single check against `issuers.keys`.

## Bundled cleanups

Small, natural byproducts of the refactor. Each is a separate commit but shares the branch.

### B1. Shared primitives for the two client-assertion verifiers

`ClientAssertionJwtClaimsVerifier` and `FederatedClientAssertionJwtClaimsVerifier` stay as distinct classes (non-goal stands: their protocol semantics genuinely differ). But both construct `requiredClaims` / `exactMatchClaims` and do audience-containment checks via near-identical code. Extract:

- `ClientAssertionClaims` — helper that returns the common required-claims set (`exp`, `iat`, `jti`) and the standard `aud`-containment check.
- Keep `expectedAudience`, `expectedIssuer`, `expectedSubject`, `maxLifetimeSeconds` as constructor params on each concrete verifier. The helper produces a `JWTClaimsSetVerifier<SecurityContext>` that each class composes into its own `verify()` implementation.

Value: one place to audit RFC 7523 required-claims. Low risk — the two classes' public constructors are unchanged.

### B2. Single env-var parse helper for issuer lists

`EnvConfiguration.kt:58-75, 141-181, 184-213` parses three issuer lists (`AUTH_PROVIDER_CONFIGS` as JSON, `FEDERATED_CLIENT_AUTH_ISSUERS` and `SUBJECT_TOKEN_ISSUERS` as CSV) with structurally similar `trim().split(",").map { ... }` patterns. Once all three feed one `IssuerJwks` registry (design #5), a single `parseIssuerList(envKey, format)` helper consolidates them.

Value: one place for error messages, trimming rules, and the "empty list = feature disabled" convention. Tiny.

## Implementation order

1. **Introduce `IssuerJwks`** alongside existing code, with boot-time JWKS warm-up + fail-fast. No call sites changed yet. Unit-test: happy path loads keys; unreachable `jwks_uri` throws; empty JWKS throws.
2. **`NimbusJwkProviderAdapter`** + unit tests proving `.get(kid)` parity with auth0 on a `MockOAuth2Server`-backed JWKS (RSA256 happy path, unknown kid, JWKS outage with stale serve).
3. **Migrate `AuthProvider` to `IssuerJwks`** — the only caller-visible change is internal; `bearerTokenVerifier` is unchanged. Run full test suite; `AuthProviderAcceptHeaderTest` is the bellwether (see Risks).
4. **Migrate `FederatedIssuer` and `SubjectTokenIssuer`** — structurally identical; they already use Nimbus, just swapping the owning type.
5. **Deduplication in `EnvConfiguration`** — build the shared issuer map. This is the functionally new behaviour; guard with a test that configures the same well-known URL in two env vars and asserts a single `.well-known` fetch (counter on `MockOAuth2Server`).
6. **Drop auth0 caching constants** (`CACHE_SIZE`, `EXPIRES_IN`, `BUCKET_SIZE`) from `AppConfiguration`; keep `com.auth0.jwk` + `com.auth0.jwt` dependencies only for Ktor DSL compatibility.
7. **B1 — extract `ClientAssertionClaims`** and fold both client-assertion verifiers onto it. Pure refactor; existing test suites guard semantics.
8. **B2 — `parseIssuerList` helper** in `EnvConfiguration`. Pure refactor.

Each step is an atomic commit. Steps 3, 4, 7, 8 are mechanical; step 5 is the one with new behaviour.

## Risks

- **`AuthProviderAcceptHeaderTest`** explicitly asserts the `Accept: application/json, application/jwk-set+json` header on JWKS fetch (`AppConfiguration.kt:99`). Nimbus's default `DefaultResourceRetriever` sends `application/json`; verify whether the test still passes, and if not, configure Nimbus with a custom retriever that preserves the header.
- **`Jwk.fromValues(jwk.toJSONObject())`** round-trips through JSON. Verify that RSA and EC key serialisations produce the same `Jwk.publicKey` / `Jwk.algorithm` the current code consumes. Unit test in step 2.
- **Shared cache coupling**: if one concern's misbehaviour poisons the shared `JWKSource` (e.g. excessive lookups triggering Nimbus's retry-with-backoff), it affects other concerns on the same issuer. Nimbus's cache is per-issuer, not per-concern, so this is by design — but log + meter JWKS fetches per `(issuer, concern)` pair to diagnose regressions.
- **Env var semantics unchanged**: `AUTH_PROVIDER_CONFIGS`, `FEDERATED_CLIENT_AUTH_ISSUERS`, `SUBJECT_TOKEN_ISSUERS` stay as independent lists. Dedup is internal. No chart/manifest changes required.
- **Boot-time fail-fast is a behaviour change**: a broken upstream IdP that was previously tolerated until first-request will now prevent startup. This is the desired policy (broken config should not silently degrade to broken traffic), but operators should be warned in the release notes. Integration tests that spin up `AppConfiguration` against a not-yet-started `MockOAuth2Server` must ensure the server is ready first.

## What this buys us

- One JWKS stack. Nimbus's outage-tolerance becomes the default for registration bearer-auth (closes a real availability gap).
- One cache per upstream IdP. A K8s cluster serving multiple concerns fetches JWKS once, refreshes once.
- Misconfigured issuers fail the deploy, not the first request that needs them.
- `IssuerJwks` becomes the natural home for the startup validations already planned (goal #4 in the federation plan): one place to enforce no-collision, no-duplicates, JWKS probe, INFO logging.
- auth0 dependencies shrink to "Ktor DSL glue". A future Ktor upgrade that accepts Nimbus `JWTProcessor` directly lets us delete the adapter.

## Out of scope — separate follow-ups

Tracked here so they don't accrete onto this refactor's commit series:

- **Test-fixture consolidation.** Many tests build `SignedJWT` / JWKs / `createClientAssertion` ad-hoc. A shared test-only `JwtFixtures` module would cut duplication, but it's test hygiene, not infrastructure. Separate PR.
- **Shared JWT signer/builder for `TokenIssuer` + tests.** `TokenIssuer` + `Extensions.sign(RSAKey)` + test-side ad-hoc builders overlap on headers, `iat`/`nbf`/`exp` defaults, and signing. A thin `JwtBuilder` would reduce drift. Separate PR once the fixture consolidation above lands.
- **`TokenExchangeApi` route handler simplification.** The `receiveTokenRequestContext { authenticateAndAuthorize { ... clientFinder = …; federatedClientFinder = …; … } }` DSL in `routing/TokenExchangeApi.kt` is vestigial: every field it plumbs is available from `AppConfiguration` at route-registration time, there's no per-request variability, and no `Authentication` plugin is actually involved. See `03-token-exchange-api-simplification.md`. Best executed after `02-` to avoid migrating `authenticateFederated` through two shapes.
