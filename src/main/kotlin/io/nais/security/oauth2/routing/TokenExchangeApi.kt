package io.nais.security.oauth2.routing

import com.nimbusds.jwt.SignedJWT
import com.nimbusds.oauth2.sdk.OAuth2Error
import io.ktor.application.call
import io.ktor.response.respond
import io.ktor.routing.Routing
import io.ktor.routing.get
import io.ktor.routing.post
import io.ktor.routing.route
import io.nais.security.oauth2.authentication.TokenExchangeRequestAuthorizer
import io.nais.security.oauth2.authentication.receiveTokenRequestContext
import io.nais.security.oauth2.config.AppConfiguration
import io.nais.security.oauth2.config.AuthorizationServerProperties.Companion.authorizationPath
import io.nais.security.oauth2.config.AuthorizationServerProperties.Companion.jwksPath
import io.nais.security.oauth2.config.AuthorizationServerProperties.Companion.tokenPath
import io.nais.security.oauth2.config.AuthorizationServerProperties.Companion.wellKnownPath
import io.nais.security.oauth2.config.path
import io.nais.security.oauth2.model.OAuth2Exception
import io.nais.security.oauth2.model.OAuth2TokenExchangeRequest
import io.nais.security.oauth2.model.OAuth2TokenRequest
import io.nais.security.oauth2.model.OAuth2TokenResponse
import io.nais.security.oauth2.model.WellKnown
import mu.KotlinLogging
import java.time.Duration
import java.time.Instant

private val log = KotlinLogging.logger { }

internal fun Routing.tokenExchangeApi(config: AppConfiguration) {
    val tokenIssuer = config.tokenIssuer

    get(wellKnownPath) {
        val issuerUrl: String = config.authorizationServerProperties.issuerUrl
        call.respond(
            WellKnown(
                issuer = issuerUrl,
                authorizationEndpoint = issuerUrl.path(authorizationPath),
                tokenEndpoint = issuerUrl.path(tokenPath),
                jwksUri = issuerUrl.path(jwksPath)
            )
        )
    }

    get(jwksPath) {
        call.respond(tokenIssuer.publicJwkSet().toJSONObject())
    }
    route(tokenPath) {
        post {
            log.debug("received call to token endpoint.")
            val tokenRequestContext = call.receiveTokenRequestContext(config.authorizationServerProperties.tokenEndpointUrl()) {
                authenticateAndAuthorize {
                    clientFinder = { config.clientRegistry.findClient(it.clientId) }
                    authorizers = listOf(
                        TokenExchangeRequestAuthorizer(config.clientRegistry)
                    )
                }
            }
            when (val tokenRequest: OAuth2TokenRequest = tokenRequestContext.oauth2TokenRequest) {
                is OAuth2TokenExchangeRequest -> {
                    val token: SignedJWT = tokenIssuer.issueTokenFor(tokenRequestContext.oauth2Client, tokenRequest)
                    call.respond(
                        OAuth2TokenResponse(
                            accessToken = token.serialize(),
                            expiresIn = token.expiresIn(),
                            scope = tokenRequest.scope
                        )
                    )
                }
                else -> throw OAuth2Exception(OAuth2Error.INVALID_GRANT.setDescription("grant_type=${tokenRequest.grantType} is not supported"))
            }
        }
    }
}

internal fun SignedJWT.expiresIn(): Int =
    Duration.between(Instant.now(), this.jwtClaimsSet.expirationTime.toInstant()).seconds.toInt()
