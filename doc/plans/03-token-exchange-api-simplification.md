# Plan: Simplify `TokenExchangeApi` Route Handler

The `/token` route handler in `routing/TokenExchangeApi.kt` uses a nested builder DSL that carries no per-request state and doesn't plug into Ktor's `Authentication` plugin. Every value it plumbs (`clientFinder`, `federatedClientFinder`, `federatedClientAuthProperties`, `acceptedAudience`, `authorizers`, `clientAssertionMaxLifetime`) is available from `AppConfiguration` at route-registration time. The DSL is vestigial.

## Why it looks the way it does

`TokenRequestContext.From.authenticateAndAuthorize` was designed as if it were a Ktor auth provider — `Configuration` class, `lateinit var acceptedAudience`, finder lambdas with a `NotImplementedError` default — but was never installed into `Authentication`. The shape of a Ktor auth DSL remained; the integration didn't. The result: every call site re-supplies the same config, via a builder that produces a one-shot `TokenRequestConfig` used for exactly one request.

## Goal

Make the `/token` handler read like the `/registration/client` handler in `ClientRegistrationApi.kt`: receive, call a service, respond. Drop the fake DSL. Keep every behavioural contract intact (self-signed dispatch, federated dispatch, claims verification, `TokenExchangeRequestAuthorizer`, `clientMap` prefetch).

## Non-goals

- Installing client-assertion auth as a real Ktor `AuthenticationProvider` (Option B in the pre-plan discussion). Form-body reading in an auth provider requires `DoubleReceive` or manual parameter caching; the symmetry payoff is too small for the friction.
- Changing `ClientAssertionJwtClaimsVerifier` / `FederatedClientAssertionJwtClaimsVerifier` / `TokenExchangeRequestAuthorizer` semantics.
- Changing the self-signed vs federated dispatch rule (`iss` lookup against `federatedClientAuthProperties.allowedIssuers`).
- Changing the two-client prefetch (`findClients(listOf(client, target))`) — carry it across as an internal detail of the new service.

## Design

### `ClientAuthenticator` — a service built once

```kotlin
class ClientAuthenticator(
    private val clientRegistry: ClientRegistry,
    private val federated: FederatedClientAuthProperties?,
    private val acceptedAudience: Set<String>,
    private val maxAssertionLifetime: Long,
) {
    data class Result(
        val client: OAuth2Client,
        val clientMap: Map<ClientId, OAuth2Client>,  // for TokenExchangeRequestAuthorizer
    )

    fun authenticate(parameters: Parameters): Result {
        val parsed = parseClientAssertion(parameters)              // was credential()
        val clientIds = ClientIDs(parsed.subject, parameters.require("audience"))
        val clientMap = clientRegistry.findClients(listOf(clientIds.client, clientIds.target))
        val client = dispatch(parsed, clientMap)                   // self-signed vs federated
        MDC.put("client_id", client.clientId)
        return Result(client, clientMap)
    }

    private fun dispatch(parsed: ParsedClientAssertion, clientMap: Map<ClientId, OAuth2Client>): OAuth2Client {
        val federatedIssuer = federated?.allowedIssuers?.get(parsed.issuer)
        return if (federatedIssuer != null) {
            authenticateFederated(parsed, federatedIssuer)         // unchanged body
        } else {
            authenticateSelfSigned(parsed, clientMap)              // unchanged body
        }
    }
}
```

`authenticateSelfSigned` and `authenticateFederated` move from `TokenRequestContext.From` onto `ClientAuthenticator` verbatim — including claims verification and the federated identity mismatch check. The only substantive change: `authenticateSelfSigned` takes the prefetched `clientMap` as a parameter and falls back to `clientRegistry.findClient(clientId)` on miss (same as today's `clientFinder` lambda).

### `TokenRequestAuthorizers` — a thin bundle

Today's `authorizers = listOf(TokenExchangeRequestAuthorizer(clientMap))` is constructed per request because it captures `clientMap`. Keep that shape, but move construction into the handler right after `authenticate` returns — not into a DSL:

```kotlin
val authorizers = listOf(TokenExchangeRequestAuthorizer(result.clientMap))
val tokenRequest = authorizers
    .find { it.supportsGrantType(parameters["grant_type"]) }
    ?.authorize(parameters, result.client)
    ?: throw OAuth2Exception(OAuth2Error.ACCESS_DENIED.setDescription("..."))
```

Two lines, no ceremony. If the authorizer list grows, extract a `TokenRequestAuthorizer.dispatch(parameters, client, clientMap)` helper. Not now.

### `TokenRequestContext` shrinks to a value type

The `TokenRequestContext` class currently carries `(oauth2Client, oauth2TokenRequest)`. That's already a plain data holder — keep it, but delete:

- `TokenRequestContext.From` (the DSL entry point)
- `TokenRequestConfig` + `TokenRequestConfig.Configuration`
- `receiveTokenRequestContext` extension
- The `clientFinder` / `federatedClientFinder` lambda types and their `NotImplementedError` defaults
- `AcceptedAudience` typealias (only used by `Configuration`)

What survives unchanged:
- `ClientCredential` sealed class
- `ParsedClientAssertion` (moves to the authentication package as internal)
- `ClientAssertionJwtClaimsVerifier` / `FederatedClientAssertionJwtClaimsVerifier`
- `TokenValidator`
- `TokenExchangeRequestAuthorizer`

### The new handler

```kotlin
route(TOKEN_PATH) {
    post {
        val parameters = call.receiveParameters()
        val result = config.clientAuthenticator.authenticate(parameters)
        val authorizers = listOf(TokenExchangeRequestAuthorizer(result.clientMap))
        val tokenRequest = authorizers
            .find { it.supportsGrantType(parameters["grant_type"]) }
            ?.authorize(parameters, result.client)
            ?: throw OAuth2Exception(
                OAuth2Error.ACCESS_DENIED.setDescription(
                    "could not find authorizer for grant_type=${parameters["grant_type"]}",
                ),
            )

        when (tokenRequest) {
            is OAuth2TokenExchangeRequest -> {
                val token = config.tokenIssuer.issueTokenFor(result.client, tokenRequest)
                call.respond(
                    OAuth2TokenResponse(
                        accessToken = token.serialize(),
                        expiresIn = token.expiresIn(),
                        scope = tokenRequest.scope,
                    ),
                )
            }
            else -> throw OAuth2Exception(
                OAuth2Error.INVALID_GRANT.setDescription("grant_type=${tokenRequest.grantType} is not supported"),
            )
        }
    }
}
```

~20 lines, structurally identical to `ClientRegistrationApi`'s handler. No DSL, no finder lambdas, no `lateinit`.

## Coupling with `02-auth-infra-unification`

`02-` changes how `FederatedClientAuthProperties` is built (references an `IssuerJwks` registry instead of owning `cacheProperties`). `ClientAuthenticator` reads `federated.allowedIssuers[iss]` and hands the result to `authenticateFederated`, which calls `TokenValidator`. After `02-`, that call becomes `TokenValidator(issuer = federatedIssuer.issuer, jwkSource = federatedIssuer.issuerJwks.jwkSource, ...)` — trivial, mechanical.

**Sequencing recommendation**: do `02-` first, then `03-`. Reasons:
- `02-` touches `FederatedIssuer`'s shape; `03-` reads that shape. Easier if it stabilises first.
- `02-`'s commit series is mechanical-heavy; `03-`'s is fewer commits but each is more opinionated. Less merge-thinking if kept sequential.
- No functional reason `03-` couldn't go first; it just means doing the federated-auth migration twice (once in the old `cacheProperties` shape, once in the new).

Doing them in parallel is also fine — the overlap is one call site in `authenticateFederated`, easy to rebase either direction.

## Implementation order

1. **Introduce `ClientAuthenticator` alongside existing code.** Constructor takes the four collaborators; `authenticate()` returns `Result`. Copy `authenticateSelfSigned`, `authenticateFederated`, `parseClientAssertion` bodies verbatim from `TokenRequestContext.From`. No call-site changes. Unit tests: self-signed happy path, federated happy path, `iss` not in whitelist → self-signed, missing `sub` → 401, lifetime exceeded → 401, federated identity mismatch → 401.
2. **Switch the `/token` handler to use `ClientAuthenticator`.** Route becomes the ~20-line form above. `receiveTokenRequestContext { authenticateAndAuthorize { ... } }` is gone from the route file. Full integration test suite guards semantics.
3. **Delete dead code in `TokenRequestContext.kt`:** `From`, `TokenRequestConfig`, `TokenRequestConfig.Configuration`, `receiveTokenRequestContext`, `AcceptedAudience`. Move `ParsedClientAssertion` to `ClientAuthenticator`'s file as `internal`. The surviving `TokenRequestContext(oauth2Client, oauth2TokenRequest)` class may itself become redundant if the handler no longer needs it — re-evaluate after step 2.
4. **Extract `ClientAuthenticator` into `AppConfiguration`.** One new field: `val clientAuthenticator: ClientAuthenticator`. Constructed from already-available config. Route handler reads `config.clientAuthenticator` instead of `config.clientRegistry` + `config.federatedClientAuthProperties` + `config.authorizationServerProperties.{tokenEndpointUrl, issuerUrl, clientAssertionMaxExpiry}`.

Each step is an atomic commit. Step 3 is the most visible — large deletion, reviewer will want the full test suite green.

## Risks

- **`TokenExchangeRequestAuthorizer(clientMap)` construction per request.** Today's code builds this inside the DSL; the new code builds it in the handler. Same lifecycle, same cost. No change.
- **MDC `client_id` placement.** Today set inside `authenticateAndAuthorize` after client resolution. Moves into `ClientAuthenticator.authenticate`. Verify it still applies for the full request span (it will — MDC propagates on the request coroutine).
- **`@WithSpan` annotations.** `TokenRequestContext.From.authenticateAndAuthorize`, `authenticateClient`, `authorizeTokenRequest` each carry `@WithSpan`. Port them to `ClientAuthenticator.authenticate` and the handler's authorizer dispatch to preserve the same span tree in traces.
- **`receiveTokenRequestContext` is a public-looking `suspend fun` extension on `ApplicationCall`.** Confirm no external callers (it's `io.nais.security.oauth2.authentication` — internal to this codebase). If anything in tests calls it directly, those tests migrate to calling `ClientAuthenticator.authenticate` on a `Parameters` fixture.
- **Behavioural equivalence under rebase.** Full `TokenExchangeApiTest` + `ClientAssertion*Test` suites must stay green across steps 1-4. Especially: unknown-grant-type error message, federated identity mismatch error message, lifetime-exceeded error message — these are asserted verbatim in tests.

## What this buys us

- The `/token` handler stops being the odd one out among the route files.
- ~80 lines of indirection removed from `TokenRequestContext.kt`.
- `ClientAuthenticator` is testable in isolation without spinning up Ktor — today's DSL requires an `ApplicationCall` context.
- The `NotImplementedError` default on `clientFinder` (a latent footgun that would explode at first request if misconfigured) disappears; the constructor either has the registry or doesn't compile.
- Natural home for future middleware-y concerns (audit logging, rate limiting by authenticated-client) once they're actually needed. Not building that abstraction now.
