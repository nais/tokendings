package io.nais.security.oauth2

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.SerializationFeature
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.oauth2.sdk.OAuth2Error
import io.ktor.application.ApplicationCall
import io.ktor.application.call
import io.ktor.auth.authenticate
import io.ktor.auth.principal
import io.ktor.response.respond
import io.ktor.routing.Routing
import io.ktor.routing.get
import io.ktor.routing.post
import io.ktor.routing.route
import io.nais.security.oauth2.authentication.ClientAuthenticationPrincipal
import io.nais.security.oauth2.authentication.OAuth2Client
import io.nais.security.oauth2.authorization.receiveAuthorizedOrFail
import io.nais.security.oauth2.config.Configuration
import io.nais.security.oauth2.config.TokenIssuerConfig
import io.nais.security.oauth2.model.OAuth2Exception
import io.nais.security.oauth2.model.OAuth2TokenExchangeRequest
import io.nais.security.oauth2.model.OAuth2TokenRequest
import io.nais.security.oauth2.model.OAuth2TokenResponse
import java.time.Duration
import java.time.Instant

object Jackson {
    val defaultMapper: ObjectMapper = jacksonObjectMapper()

    init {
        defaultMapper.configure(SerializationFeature.INDENT_OUTPUT, true)
    }
}

internal fun Routing.tokenExchangeApi(config: Configuration) {
    val tokenIssuer = config.tokenIssuerConfig.tokenIssuer

    get(TokenIssuerConfig.wellKnownPath) {
        call.respond(config.tokenIssuerConfig.wellKnown)
    }

    get(TokenIssuerConfig.jwksPath) {
        call.respond(tokenIssuer.publicJwkSet().toJSONObject())
    }

    route(TokenIssuerConfig.tokenPath) {
        authenticate("oauth2ClientAuth") {
            post {
                val client: OAuth2Client = call.authenticatedClient()

                when (val tokenRequest: OAuth2TokenRequest = call.receiveAuthorizedOrFail()) {
                    is OAuth2TokenExchangeRequest -> {
                        val token: SignedJWT = tokenIssuer.issueTokenFor(client, tokenRequest)
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
}

private fun ApplicationCall.authenticatedClient(): OAuth2Client =
    principal<ClientAuthenticationPrincipal>()?.oauth2Client ?: throw OAuth2Exception(OAuth2Error.INVALID_CLIENT)

fun SignedJWT.expiresIn(): Int =
    Duration.between(Instant.now(), this.jwtClaimsSet.expirationTime.toInstant()).seconds.toInt()
