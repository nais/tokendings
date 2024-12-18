package io.nais.security.oauth2.routing

import com.nimbusds.jwt.SignedJWT
import com.nimbusds.oauth2.sdk.OAuth2Error
import io.ktor.server.response.respond
import io.ktor.server.routing.Routing
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.route
import io.nais.security.oauth2.authentication.TokenExchangeRequestAuthorizer
import io.nais.security.oauth2.authentication.receiveTokenRequestContext
import io.nais.security.oauth2.config.AppConfiguration
import io.nais.security.oauth2.config.AuthorizationServerProperties.Companion.AUTHORIZATION_PATH
import io.nais.security.oauth2.config.AuthorizationServerProperties.Companion.JWKS_PATH
import io.nais.security.oauth2.config.AuthorizationServerProperties.Companion.TOKEN_PATH
import io.nais.security.oauth2.config.AuthorizationServerProperties.Companion.WELL_KNOWN_PATH
import io.nais.security.oauth2.config.path
import io.nais.security.oauth2.model.OAuth2Exception
import io.nais.security.oauth2.model.OAuth2TokenExchangeRequest
import io.nais.security.oauth2.model.OAuth2TokenRequest
import io.nais.security.oauth2.model.OAuth2TokenResponse
import io.nais.security.oauth2.model.WellKnown
import io.nais.security.oauth2.token.expiresIn
import io.opentelemetry.api.trace.SpanKind
import io.opentelemetry.instrumentation.annotations.WithSpan
import mu.KotlinLogging

private val log = KotlinLogging.logger { }

@WithSpan(kind = SpanKind.SERVER)
internal fun Routing.tokenExchangeApi(config: AppConfiguration) {
    val tokenIssuer = config.tokenIssuer

    get(WELL_KNOWN_PATH) {
        val issuerUrl: String = config.authorizationServerProperties.issuerUrl
        call.respond(
            WellKnown(
                issuer = issuerUrl,
                authorizationEndpoint = issuerUrl.path(AUTHORIZATION_PATH),
                tokenEndpoint = issuerUrl.path(TOKEN_PATH),
                jwksUri = issuerUrl.path(JWKS_PATH),
            ),
        )
    }

    get(JWKS_PATH) {
        call.respond(tokenIssuer.publicJwkSet().toJSONObject())
    }

    route(TOKEN_PATH) {
        post {
            log.debug("received call to token endpoint.")
            val tokenRequestContext =
                call.receiveTokenRequestContext(config.authorizationServerProperties.tokenEndpointUrl()) {
                    authenticateAndAuthorize { clientIds ->
                        val clientMap = config.clientRegistry.findClients(listOf(clientIds.client, clientIds.target))
                        clientFinder = { clientAssertionCredential -> clientMap[clientAssertionCredential.clientId] }

                        authorizers =
                            listOf(
                                TokenExchangeRequestAuthorizer(clientMap),
                            )
                        clientAssertionMaxLifetime = config.authorizationServerProperties.clientAssertionMaxExpiry
                    }
                }
            when (val tokenRequest: OAuth2TokenRequest = tokenRequestContext.oauth2TokenRequest) {
                is OAuth2TokenExchangeRequest -> {
                    val token: SignedJWT = tokenIssuer.issueTokenFor(tokenRequestContext.oauth2Client, tokenRequest)
                    call.respond(
                        OAuth2TokenResponse(
                            accessToken = token.serialize(),
                            expiresIn = token.expiresIn(),
                            scope = tokenRequest.scope,
                        ),
                    )
                }
                else -> throw OAuth2Exception(
                    OAuth2Error.INVALID_GRANT.setDescription(
                        "grant_type=${tokenRequest.grantType} is not supported",
                    ),
                )
            }
        }
    }
}
