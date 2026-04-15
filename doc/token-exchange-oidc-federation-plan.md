# Plan: OIDC Federated Token Support for Token Exchange API

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

- Add a simple config property: `allowedFederatedIssuers: Map<String, JwkProvider>` — a map from issuer URL to a cached/rate-limited `JwkProvider` (for JWKS fetching), built via discovery from well-known URLs.
- Wire from `EnvConfiguration` as a list of allowed issuer well-known URLs.
- No cluster mappings or per-provider subject restrictions — that's the registrar's job.
- Reuse `JwkProviderBuilder` with caching/rate-limiting as done in `AuthProvider.fromWellKnown()`.

### 2. Model — Extend `SoftwareStatement` with optional federated identity

**File**: `ClientRegistration.kt`

- Add optional fields to `SoftwareStatement`: `federatedIssuer: String?` and `federatedSubject: String?`.
- These are set by the registrar (jwker) when the client should use federated auth.
- Add these to the required claims verification in `verifySoftwareStatement()` (as optional claims).

**File**: `OAuth2Client.kt`

- Add optional field: `federatedIdentity: FederatedIdentity?` containing `issuer: String` and `subject: String`.
- Default to `null` for backwards compatibility — existing JSON in the DB deserializes fine (Jackson ignores missing fields).
- Allow JWKS-only, federated-only, or both auth methods per client.

**Registration invariant**: A client must have at least one auth method:
- Non-empty JWKS, or
- Federated identity

Reject registrations with empty JWKS and no federated identity.

### 3. Client Registration — Store federated identity from software statement

**File**: `ClientRegistrationApi.kt`

- After verifying the software statement, read `federatedIssuer` and `federatedSubject` from it.
- If present, validate that the issuer is in tokendings' allowed issuers whitelist. Reject if not.
- Store the `FederatedIdentity` on the `OAuth2Client`.
- Relax JWKS validation: if federated identity is present in the software statement, allow empty JWKS in the request.

### 4. Token Request Authentication — Dual-path client auth

**File**: `TokenRequestContext.kt`

This is the core change. `credential()` and `authenticateClient()` need to support two paths:

- **Path A (existing/self-signed)**: Parse `client_assertion` JWT. `iss` does not match any allowed federated issuer → extract `clientId` from `sub` → find client by `clientId` → verify signature against `oAuth2Client.jwkSet`.
- **Path B (federated)**: Parse `client_assertion` JWT. `iss` matches an allowed federated issuer → verify signature against the issuer's JWKS (via `JwkProvider`) → find `OAuth2Client` by matching `federatedIdentity.issuer` + `federatedIdentity.subject` to the JWT's `iss` + `sub` claims → verify the client's stored `federatedIdentity` matches.

**Implementation approach**:
- Extract `credential()` into a sealed type: `ClientCredential` with subtypes `SelfSignedAssertion` (existing) and `FederatedAssertion` (new).
- Add a new `clientFinder` path for federated tokens that queries the client registry by federated identity.
- Reuse `bearerTokenVerifier`-style logic from `BearerTokenAuthenticationConfiguration.kt` to verify the federated JWT against the provider's JWKS.

**Runtime fail-fast rules**:
- Self-signed path must fail fast if client has no JWKS.
- Federated path must fail fast if client has no federated identity.

### 5. Client Registry — Query by federated identity

**Files**: `ClientStore.kt`, `ClientRegistry` interface

- Add `findByFederatedIdentity(issuer: String, subject: String): OAuth2Client?` method.
- Add dedicated nullable columns `federated_issuer` and `federated_subject` with a unique composite index for fast lookup and uniqueness enforcement.
- Requires a Flyway migration to add the columns and index.

### 6. Federated Claims Verifier

Do not reuse the existing `ClientAssertionJwtClaimsVerifier` unchanged — it assumes `iss == sub == clientId`.

Federated verifier must validate:
- Signature against the issuer's JWKS (fetched via `JwkProvider` from the allowed issuers map)
- `iss` equals a whitelisted issuer
- `sub` present and non-empty
- `aud` contains tokendings token endpoint URL
- `exp` valid with bounded max lifetime
- `iat` valid

### 7. Token Exchange API — Wire the new config

**File**: `TokenExchangeApi.kt`

- Pass the allowed federated issuers map into the `authenticateAndAuthorize` block.
- Update the `clientFinder` lambda to support both lookup-by-clientId (existing) and lookup-by-federated-identity (new).

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

### Risks and open questions

- **Audience validation is critical**: Define exactly what `aud` must be for federated client auth and document it for clients.
- **Provider `sub` stability**: Confirm the external provider's `sub` claim is stable and not subject to pairwise/rotation behavior.
- **Replay risk**: If federated assertions live longer than current client assertions, consider stricter lifetime bounds or `jti` replay handling.
- **Uniqueness must be DB-enforced**: A given `(issuer, subject)` must not map to multiple tokendings clients — use DB-level unique constraint.
