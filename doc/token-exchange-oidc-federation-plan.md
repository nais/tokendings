# Plan: OIDC Federated Token Support for Token Exchange API

## Status (as of commit `305fc85` on `token-exchange-oidc-federation`)

**Vertical slice shipped**: token-exchange side of OIDC federation works end-to-end for the happy path. Existing clients are unaffected (all 78 tests pass).

### Done

| # | Commit | Scope |
|---|---|---|
| 1 | `ca48d51` | **feat(db)** — `V3__add_federated_identity.sql`: nullable `federated_issuer`/`federated_subject` columns + partial unique index on `(federated_issuer, federated_subject) WHERE ... IS NOT NULL`. |
| 2 | `6435307` | **feat(model)** — `FederatedIdentity` on `OAuth2Client`, `@JsonInclude(NON_NULL)` to avoid JSONB churn on existing rows, SerDe tests. |
| 3 | `e15c924` | **feat(registry)** — `findClientByFederatedIdentity` on all `ClientRegistry` impls; upsert writes the new columns; store tests. |
| 4 | `55d081c` | **feat(config)** — `FederatedClientAuthProperties` (map-of-issuers whitelist, audience, `maxAssertionLifetimeSeconds` default 600s), `FederatedIssuer.fromWellKnown` eager resolution, `buildCachedJwkProvider` helper, env wiring. |
| 5 | `2337446` | **feat(auth)** — `FederatedClientAssertionJwtClaimsVerifier` (no `jti`/`nbf` required, `aud` contains-check, K8s-token friendly) + 7 unit tests. |
| 6 | `ac3a7af` | **test(db)** — bump expected migration count 2 → 3. |
| 7 | `731092f` | **feat(auth)** — dual-path dispatch in `TokenRequestContext`: sealed `ClientCredential` with `SelfSigned`/`Federated` variants, `iss`-whitelist dispatch, auth0 `Jwk` → Nimbus `JWKSet` bridging via `RSAPublicKey`, `findClientByFederatedIdentity` lookup, federated-identity mismatch guard, MDC `client_id` moved post-auth. |
| 8 | `305fc85` | **test(auth)** — happy-path integration test on `/token`: `MockOAuth2Server` acts as a federated issuer, a client is registered with a matching `FederatedIdentity`, a K8s-shaped assertion (`expiry=300s`) authenticates and token-exchange returns 200 with the target client's audience. |
| 9 | `8f3d2ec` | **refactor(auth)** — `FederatedIssuer` now uses Nimbus `CacheProperties` + `JWKSource` (stale-tolerant, refresh-ahead, retrying) mirroring `SubjectTokenIssuer`, instead of auth0 `JwkProvider`. `authenticateFederated` verifies via `JWSVerificationKeySelector` — no more manual `Jwk` → `RSAPublicKey` → `RSAKey.Builder` bridging, no explicit `kid` handling. |

### Key discoveries (locked in)

- `MockOAuth2Server.issueToken(issuerId, subject, DefaultOAuth2TokenCallback(issuerId=..., subject=..., audience=listOf(...), expiry=<=600))` fully simulates a federated OIDC issuer. `iss` claim equals `issuerUrl(issuerId).toString()`.
- Nimbus `JWKSourceBuilder` (used via `CacheProperties`) is `.outageTolerantForever()`, refresh-ahead, and retries on transient failures — preferred over auth0's `JwkProvider` for federated issuer JWKS. `AuthProvider` (bearer auth on registration) still uses auth0; refactoring that is a separate concern.
- auth0 `JwkProviderBuilder.cached(...)` does **not** serve stale on upstream failure. Only relevant where auth0 is still used.
- `TokenExchangeRequestAuthorizer.targetClients` is audience-keyed; the authenticated federated client doesn't need to be in that map — `clientFinder` falls back to `config.clientRegistry.findClient(clientId)`.
- `DefaultOAuth2TokenCallback` defaults to 3600s expiry; federated tests must pass `expiry <= 600`.

### Remaining goals (recommended order)

1. **Negative federated tests** (`TokenExchangeApiTest`): wrong audience, expired assertion, unknown issuer (not in whitelist), unregistered `(iss, sub)`, federated-identity mismatch between JWT and stored client, lifetime exceeded. Low risk, high confidence.
2. **Security test — impersonation guard**: federated assertion with `sub == someVictimClientId` (a legacy self-signed client's id) must NOT authenticate as that client. Locks in the oracle-flagged concern.
3. **Registration-side changes** (`ClientRegistrationApi.kt`, `ClientRegistration.kt`):
   - Add optional `federatedIssuer` / `federatedSubject` to `SoftwareStatement` + verifier.
   - Fix validation ordering: move JWKS emptiness check to *after* software-statement verification; enforce "at least one auth method" invariant.
   - Add `AuthProvider.allowedFederatedIssuers: Set<String>?` trust boundary (prevents cross-cluster registrar impersonation).
   - Persist `FederatedIdentity` on the `OAuth2Client` on register/update.
4. **Observability** (step 8 below): `client_auth_path` metric, JWKS fetch latency/error metric + alert, `federated_jti_duplicate_observations`, log fields, span attribute.
5. **Docs for client teams**: K8s projected-SA-token audience must equal `federatedAssertionAudience`; no re-signing; forward as-is in `client_assertion`.

### Deferred (not blocking phase 1)

- Full replay cache (drive by `federated_jti_duplicate_observations` metric first).
- Phase 3 JWKS cleanup tooling (clients dropping self-signed auth).
- JSONB trigger vs. columns-authoritative was decided in favour of **columns authoritative** — no trigger to maintain.

---

## Background

The client registration API (`ClientRegistrationApi.kt`) recently added support for external OIDC auth providers via Bearer token authentication. We now want to bring similar functionality to the token exchange API (`TokenExchangeApi.kt`), with backwards compatibility — existing clients with registered public JWKS must continue to function and may migrate at their own pace.

## Current State

- **Token exchange client auth**: Clients send `client_assertion` (a self-signed JWT) + `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`. Tokendings verifies the signature against the client's stored JWKS (`OAuth2Client.jwkSet`). The `clientId` is extracted from the JWT `sub` claim (`TokenRequestContext.kt:153`).
- **Client registration auth**: Already supports external OIDC providers via Bearer token auth. Uses `AuthProvider` (configured from well-known URLs), validated in `BearerTokenAuthenticationConfiguration.kt`.
- **`OAuth2Client` model**: Only stores `jwks` — no concept of a federated identity provider.

## Design Decision: Auth Path Dispatch via `iss` Claim

After reviewing the alternatives, the chosen approach is to dispatch the authentication path by inspecting the `iss` claim of the `client_assertion` JWT:

- If `iss` matches a configured OIDC provider → **federated path** (verify against provider JWKS)
- Otherwise → **self-signed path** (verify against client's stored JWKS, existing behavior)

### Why this approach

Self-signed assertions use `iss == clientId` (e.g., `dev-gcp:myteam:myapp`), while OIDC provider issuers are URLs (e.g., `https://login.microsoftonline.com/...`). These are structurally different and will never collide. A forged `iss` still fails signature verification against the provider's JWKS, so there is no security risk.

### Alternatives considered

| Option | Dispatch mechanism | Client change required | Standards basis |
|---|---|---|---|
| **A** — new assertion type | `client_assertion_type` value | Must change assertion type | RFC 7521 §4.2 |
| **B** — `client_id` param | `client_id` param → client lookup → check capabilities | Must add `client_id` param | RFC 7521 §4.2 + RFC 6749 §2.3 |
| **C** — Bearer header | Auth scheme (Bearer vs body assertion) | Different auth mechanism | RFC 6749 §2.3 (custom scheme) |
| **`iss` sniffing (chosen)** | JWT `iss` claim matches configured provider | **None** | RFC 6749 §2.3 |

Options A, B, and C all require clients to change something. The `iss` sniffing approach requires zero client-side changes for both existing and federated clients, making it the most pragmatic choice for backwards-compatible migration.

### Relevant RFC context

- **RFC 6749 §2.3**: The authorization server MAY support any suitable HTTP authentication scheme. When using other authentication methods, the authorization server MUST define a mapping between client identifier and authentication scheme.
- **RFC 7521 §4.2**: Defines assertion-based client auth with optional `client_id` for identification.
- **RFC 6750**: Defines `Authorization: Bearer` for resource access only, not client authentication.

## Key Design Principle: Registrar Owns the Mapping

The federated identity mapping (which OIDC issuer + subject corresponds to which client) is the **registrar's responsibility** (jwker/nais-system), expressed through the **software statement**. Tokendings does not maintain per-provider configurations with cluster mappings — it only has a **whitelist of allowed issuers** and fetches their JWKS for signature verification.

This means:
- The registrar decides which clients get federated identities and encodes this in the signed software statement.
- Tokendings trusts the software statement (already verified against `softwareStatementJwks`) and simply checks that the declared issuer is in its allowed list.
- Adding new providers or changing client-to-issuer mappings requires no tokendings configuration changes — only software statement changes from the registrar.

## Implementation Plan

### 1. Configuration — Allowed federated issuers whitelist

**File**: `AppConfiguration.kt`

- Add a config property: `allowedFederatedIssuers: Map<String, JwkProvider>` — a map from issuer URL to a cached/rate-limited `JwkProvider` (for JWKS fetching).
- Add a config property: `federatedAssertionAudience: String` — the required `aud` value for federated client assertions, configured via environment variable.
- Add a config property: `federatedAssertionMaxLifetime: Long` — max lifetime in seconds for federated assertions. Must accommodate Kubernetes service account tokens which have a minimum of 600s. Suggested default: `600L` (or higher to provide headroom).
- **Resolve at startup**: Like `AuthProvider.fromWellKnown` and `SubjectTokenIssuer`, fetch each well-known document eagerly at construction time (via `runBlocking` + `retryingHttpClient`) and build the `JwkProvider` pointing at the discovered `jwks_uri`. This fails fast on misconfiguration and avoids cold-start latency on the first federated request.
- Wire from `EnvConfiguration` as a list of allowed issuer well-known URLs plus the audience and lifetime values.
- No cluster mappings or per-provider subject restrictions — that's the registrar's job (but see step 3 for the registrar-to-issuer trust boundary).
- Reuse `JwkProviderBuilder` with caching/rate-limiting as done in `AuthProvider.fromWellKnown()`.

**Operational note**: `auth0`'s `JwkProviderBuilder.cached(...)` does not serve stale on upstream failure. A JWKS outage for a whitelisted issuer will fail federated auth for that issuer until recovery. Plan alerting for this (see step 8).

### 2. Model — Extend `SoftwareStatement` and `OAuth2Client` with optional federated identity

**File**: `ClientRegistration.kt`

- Add optional fields to `SoftwareStatement`: `federatedIssuer: String?` and `federatedSubject: String?`.
- These are set by the registrar (jwker) when the client should use federated auth.
- Add these to the required claims verification in `verifySoftwareStatement()` (as optional claims).

**File**: `OAuth2Client.kt`

- Add optional field: `federatedIdentity: FederatedIdentity?` containing `issuer: String` and `subject: String`.
- Default to `null` for backwards compatibility.
- **Add `@JsonInclude(JsonInclude.Include.NON_NULL)` at the class level** to prevent emitting `"federatedIdentity": null` for legacy clients — otherwise every existing row's `data` column would flip on first touch after deploy (data churn + cache invalidation).
- Add a regression test that deserializes a pre-migration JSON blob to verify Jackson + Kotlin default-args handles it cleanly.
- Allow JWKS-only, federated-only, or both auth methods per client.

**Registration invariant**: A client must have at least one auth method:
- Non-empty JWKS, or
- Federated identity

Reject registrations with empty JWKS and no federated identity.

### 3. Client Registration — Store federated identity from software statement

**File**: `ClientRegistrationApi.kt`

- **Fix validation ordering**: The current `request.validate()` at line 33 rejects empty JWKS *before* the software statement is parsed. Move the JWKS check to after `verifySoftwareStatement()` and enforce the real invariant: "at least one of non-empty JWKS or federated identity". Also: `JsonWebKeys.keys` is currently non-nullable `List<JWK>`; decide whether to accept `{"keys": []}` or make `jwks` nullable in `ClientRegistrationRequest`.
- After verifying the software statement, read `federatedIssuer` and `federatedSubject` from it.
- Validate that `federatedIssuer` is in tokendings' allowed issuers whitelist. Reject if not.
- **Registrar-to-issuer trust boundary**: Extend `AuthProvider` with `allowedFederatedIssuers: Set<String>?` (nullable = allow all whitelisted issuers for this registrar). Enforce during registration: the calling registrar must be permitted to declare the given `federatedIssuer`. Without this, a compromised registrar in cluster A could register a client with a `federatedIdentity` pointing to cluster B's K8s issuer + a victim subject. Mirrors the existing `allowedClusterName` constraint on `appId`.
- Store the `FederatedIdentity` on the `OAuth2Client`.

### 4. Token Request Authentication — Dual-path client auth

**File**: `TokenRequestContext.kt`

This is the core change. The current flow is **extract clientId from JWT `sub` → pre-fetch client → verify**. For federated assertions, `sub` is the external subject (e.g., `system:serviceaccount:team:app`), not a Nais clientId — so the current ordering breaks.

**Revised ordering**:

- **Path A (existing/self-signed)**: Parse `client_assertion` JWT. `iss` does not match any allowed federated issuer → extract `clientId` from `sub` → find client by `clientId` → verify signature against `oAuth2Client.jwkSet`.
- **Path B (federated)**: Parse `client_assertion` JWT. `iss` matches an allowed federated issuer → verify signature against the issuer's JWKS (via `JwkProvider`) → verify claims via the federated claims verifier → look up `OAuth2Client` via `findByFederatedIdentity(iss, sub)` → verify the returned client's stored `federatedIdentity` matches the JWT claims.

**Implementation approach**:
- Extract `credential()` into a sealed `ClientCredential` with `SelfSignedAssertion` and `FederatedAssertion` variants.
- `ClientCredential` **must not expose `clientId` directly for the federated path** — the Nais clientId is only known *after* lookup. Expose a `resolveClient(...)` method per variant that returns the resolved `OAuth2Client`.
- Downstream code (MDC logging, `ClientIDs`, `clientFinder`, `TokenExchangeRequestAuthorizer`) must consume the resolved `OAuth2Client.clientId`, never the raw JWT `sub` on the federated path.
- **Move `clientMap` pre-fetch out of `TokenExchangeApi.kt`**: Today `TokenExchangeApi.kt:56` pre-fetches `findClients(listOf(clientIds.client, clientIds.target))` using the unverified `sub`. This must either happen *after* the authenticated client is resolved, or be extended to include the federated-resolved client. Otherwise `accessPolicyInbound.contains(authenticatedClient.clientId)` checks in `TokenExchangeRequestAuthorizer` will fail on federated requests.
- **MDC put**: `TokenRequestContext.kt:62` puts the unverified `sub` into MDC before verification. Consider moving this after verification (or tagging as "claimed") — otherwise federated subjects from unverified tokens land in logs.
- Reuse `bearerTokenVerifier`-style logic from `BearerTokenAuthenticationConfiguration.kt` for JWKS-based verification. Map fetch failures to `invalid_client` (per RFC 6749 at the token endpoint), not `invalid_request`.

**Runtime fail-fast rules**:
- Self-signed path must fail fast if client has no JWKS.
- Federated path must fail fast if client has no federated identity.
- **Security test**: Add a test proving a federated assertion with `sub == someVictimClientId` cannot authenticate as that client unless the client has explicitly registered exactly that `(iss, sub)` federated identity.

### 5. Client Registry — Query by federated identity

**Files**: `ClientStore.kt`, `ClientRegistry` interface

- Add `findByFederatedIdentity(issuer: String, subject: String): OAuth2Client?` method.
- Add dedicated nullable columns `federated_issuer` and `federated_subject`.
- Enforce a **unique composite constraint** on `(federated_issuer, federated_subject)` where both are non-null, via a partial unique index (e.g., `CREATE UNIQUE INDEX ... WHERE federated_issuer IS NOT NULL AND federated_subject IS NOT NULL`).
- **Extend the upsert SQL to write the new columns** — today `storeClient` only writes `data`. Without this, the indexed columns stay null and lookups fail silently.
- **Decide authority**: JSONB as source of truth (with a trigger populating columns from `data`) OR columns authoritative (and remove `federatedIdentity` from the JSONB blob). Don't let them drift. Recommendation: columns authoritative for federated identity (simpler semantics, DB-enforceable, no trigger to maintain).
- Requires a Flyway migration to add the columns and index.

### 6. Federated Claims Verifier

Do not reuse the existing `ClientAssertionJwtClaimsVerifier` unchanged — it assumes `iss == sub == clientId` and requires `aud.size == 1` plus `jti`/`nbf`. Kubernetes projected SA tokens don't include `jti` and may have multiple audiences.

Federated verifier must validate:
- Signature against the issuer's JWKS (fetched via `JwkProvider` from the allowed issuers map)
- `iss` equals a whitelisted issuer
- `sub` present and non-empty
- `aud` **contains** the configured `federatedAssertionAudience` (don't require `aud.size == 1`; RFC 7523 allows multi-value)
- `exp` valid
- `iat` valid
- Required claims: `iss, sub, aud, exp, iat`. Do **not** require `jti`. `nbf` is typically present in K8s tokens but should not be required.
- Lifetime bounded by `federatedAssertionMaxLifetime` (default 600s to accommodate Kubernetes SA tokens; separate from the existing 120s `clientAssertionMaxExpiry` used for self-signed assertions)

### 7. Token Exchange API — Wire the new config

**File**: `TokenExchangeApi.kt`

- Pass the allowed federated issuers map into the `authenticateAndAuthorize` block.
- Update the `clientFinder` lambda to support both lookup-by-clientId (existing) and lookup-by-federated-identity (new).
- Restructure the `clientMap` pre-fetch per step 4 so it works for both auth paths.

### 8. Observability

- Metric: `client_auth_path{path=self_signed|federated, outcome=success|failure}` on the token endpoint.
- Metric: `federated_jwks_fetch_latency{issuer}` and error counter.
- Metric: `federated_jti_duplicate_observations` — count duplicate `jti` values seen within the assertion lifetime window. Enables evidence-based decision on whether to add a full replay cache.
- Log field: `federated_iss`, `federated_sub` on the federated path (alongside `client_id`).
- Span attribute: `auth.path` on the `authenticateClient` span.
- Alert: sudden drop in self-signed success rate after deploy (regression canary).
- Alert: elevated JWKS fetch errors per issuer (upstream outage).

## Migration Strategy

1. **Phase 1 — Deploy with dual support**: Clients can be registered with JWKS (existing), federated identity, or both. Token endpoint accepts both auth methods.
2. **Phase 2 — Clients migrate**: Clients re-register with federated identity at their own pace. They can keep JWKS during transition.
3. **Phase 3 — Optional cleanup**: Clients can drop JWKS and use federated-only auth.

## Council Review Summary

The plan was reviewed by a multi-LLM council (claude-opus-4.6 + gemini-3.1-pro-preview). Key feedback incorporated:

### Approved
- Dual-path auth with gradual migration
- Reusing `AuthProvider` infrastructure
- Optional `federatedIdentity` on `OAuth2Client`
- Phased migration strategy

### Council recommended changes (and our response)

1. **"Don't rely on `iss` sniffing"** — Council recommended explicit `client_assertion_type` or `client_id` parameter instead. **Decision: We keep `iss` sniffing** because issuer collision is not a realistic risk (namespace-format client IDs vs URL-format provider issuers), and it's the only approach requiring zero client-side changes.

2. **"Don't use JSONB-only lookup for federated identity"** — **Accepted.** Plan includes dedicated indexed DB columns for `federated_issuer` + `federated_subject` with a unique composite constraint.

3. **"Use separate claims verifier for federated assertions"** — **Accepted.** Added as step 6.

4. **"Define strict registration invariants"** — **Accepted.** Require at least one auth method; fail fast at runtime if wrong path is attempted.

### Resolved decisions

- **Audience**: The required `aud` for federated assertions is configurable via environment variable (`federatedAssertionAudience`). Documented for the registrar to include in software statements / client onboarding.
- **Provider `sub` stability**: Assumed stable. Stability is the registrar's concern (it controls which `sub` values get mapped to clients via the software statement).
- **Federated assertion lifetime**: Configurable via `federatedAssertionMaxLifetime`, default 600s to accommodate Kubernetes service account tokens (minimum 600s). Kept separate from the 120s `clientAssertionMaxExpiry` used for self-signed assertions.
- **Uniqueness**: Enforced at the DB level via a partial unique index on `(federated_issuer, federated_subject)`.

### Remaining considerations

- **Replay risk with longer-lived assertions**: 600s+ lifetime increases replay window vs. 120s. The plan instruments duplicate-`jti` observations (step 8) as an evidence-gathering step. Promote to a full replay cache if metrics show misuse or if threat modeling requires it pre-prod.
- **K8s ServiceAccountToken projection**: Document for client teams — the projected volume must declare `audience = federatedAssertionAudience`. Clients forward the mounted token as-is in `client_assertion`; no re-signing needed.
- **Registrar software-statement signing key scope**: Multiple registrars sharing the same software-statement signing key means they share the trust boundary for declaring federated identities. The `allowedFederatedIssuers` constraint on `AuthProvider` (step 3) mitigates cross-cluster impersonation.
