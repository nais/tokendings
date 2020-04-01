package io.nais.security.oauth2

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.SerializationFeature
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.oauth2.sdk.OAuth2Error
import io.ktor.application.Application
import io.ktor.application.ApplicationCall
import io.ktor.application.call
import io.ktor.application.install
import io.ktor.auth.Authentication
import io.ktor.auth.authenticate
import io.ktor.auth.principal
import io.ktor.features.ContentNegotiation
import io.ktor.http.ContentType
import io.ktor.http.Parameters
import io.ktor.jackson.JacksonConverter
import io.ktor.request.receiveParameters
import io.ktor.response.respond
import io.ktor.routing.get
import io.ktor.routing.post
import io.ktor.routing.route
import io.ktor.routing.routing
import io.nais.security.oauth2.Jackson.defaultMapper
import io.nais.security.oauth2.authentication.ClientAuthenticationPrincipal
import io.nais.security.oauth2.authentication.ClientRegistry
import io.nais.security.oauth2.authentication.OAuth2Client
import io.nais.security.oauth2.authentication.oauth2ClientAuth
import io.nais.security.oauth2.config.Configuration
import io.nais.security.oauth2.config.TokenIssuerConfig
import io.nais.security.oauth2.model.GrantType.tokenExchangeGrant
import io.nais.security.oauth2.model.OAuth2Exception
import io.nais.security.oauth2.model.OAuth2TokenRequest
import io.nais.security.oauth2.model.OAuth2TokenResponse
import io.nais.security.oauth2.model.TokenType.tokenTypeJwt
import io.nais.security.oauth2.token.TokenIssuer
import mu.KotlinLogging
import java.time.Duration
import java.time.Instant

private val log = KotlinLogging.logger {}

object Jackson {
    val defaultMapper: ObjectMapper = jacksonObjectMapper()

    init {
        defaultMapper.configure(SerializationFeature.INDENT_OUTPUT, true)
    }
}

internal fun Application.tokenExchangeApi(config: Configuration) {

    val tokenIssuer = TokenIssuer(config.tokenIssuerConfig, config.tokenValidatorConfig)
    val clientRegistry = ClientRegistry(config.tokenIssuerConfig, emptyList())

    install(ContentNegotiation) {
        register(ContentType.Application.Json, JacksonConverter(defaultMapper))
    }

    install(Authentication) {
        oauth2ClientAuth("oauth2ClientAuth") {
            validate { credential ->
                clientRegistry.authenticate(credential)
            }
        }
    }

    routing {

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
                    val tokenRequest: OAuth2TokenRequest = call.receiveTokenRequest()
                    val token: SignedJWT = tokenIssuer.issueTokenFor(client, tokenRequest)
                    call.respond(
                        OAuth2TokenResponse(
                            accessToken = token.serialize(),
                            expiresIn = token.expiresIn(),
                            scope = tokenRequest.scope
                        )
                    )
                }
            }
        }
    }
}

private suspend fun ApplicationCall.authenticatedClient(): OAuth2Client =
    principal<ClientAuthenticationPrincipal>()?.oauth2Client ?: throw OAuth2Exception(OAuth2Error.INVALID_CLIENT)

private suspend fun ApplicationCall.receiveTokenRequest(): OAuth2TokenRequest {
    val formParams: Parameters = receiveParameters()
    return OAuth2TokenRequest(
        formParams.require("grant_type", tokenExchangeGrant),
        formParams.require("subject_token_type", tokenTypeJwt),
        formParams.require("subject_token"),
        formParams.require("audience"),
        formParams["resource"],
        formParams["scope"]
    )
}

@Throws(OAuth2Exception::class)
private fun Parameters.require(name: String, requiredValue: String? = null): String =
    when {
        requiredValue != null -> {
            this[name]
                ?.filter { it.toString() == requiredValue }
                ?: throw OAuth2Exception(OAuth2Error.INVALID_REQUEST.setDescription("Parameter $name must be $requiredValue"))
        }
        else -> {
            this[name] ?: throw OAuth2Exception(OAuth2Error.INVALID_REQUEST.setDescription("Parameter $name missing"))
        }
    }

fun SignedJWT.expiresIn(): Int =
    Duration.between(Instant.now(), this.jwtClaimsSet.expirationTime.toInstant()).seconds.toInt()
