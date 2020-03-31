package io.nais.security.oauth2

import com.nimbusds.jwt.SignedJWT
import com.nimbusds.oauth2.sdk.ErrorObject
import com.nimbusds.oauth2.sdk.OAuth2Error
import io.ktor.application.Application
import io.ktor.application.ApplicationCall
import io.ktor.application.call
import io.ktor.application.install
import io.ktor.auth.Authentication
import io.ktor.auth.authenticate
import io.ktor.http.Parameters
import io.ktor.request.receiveParameters
import io.ktor.response.respond
import io.ktor.routing.get
import io.ktor.routing.post
import io.ktor.routing.route
import io.ktor.routing.routing
import io.nais.security.oauth2.authentication.ClientRegistry
import io.nais.security.oauth2.authentication.oauth2ClientAuth
import io.nais.security.oauth2.config.Configuration
import io.nais.security.oauth2.config.IssuerConfig
import io.nais.security.oauth2.jwt.JwtTokenIssuer
import io.nais.security.oauth2.jwt.JwtTokenValidator
import io.nais.security.oauth2.model.OAuth2TokenResponse
import mu.KotlinLogging
import java.time.Duration
import java.time.Instant

private val log = KotlinLogging.logger {}

internal fun Application.tokenExchangeApi(config: Configuration) {

    val jwtTokenValidator = JwtTokenValidator()
    val jwtTokenIssuer = JwtTokenIssuer(config.issuerConfig.issuerUrl)
    val clientRegistry = ClientRegistry(config.issuerConfig, emptyList())

    install(Authentication) {
        oauth2ClientAuth("oauth2Client") {
            validate { credential ->
                clientRegistry.authenticate(credential)
            }
        }
    }

    routing {

        get(IssuerConfig.wellKnownPath) {
            call.respond(config.issuerConfig.wellKnown)
        }

        get(IssuerConfig.jwksPath) {
            call.respond(jwtTokenIssuer.publicJwkSet().toJSONObject())
        }

        route(IssuerConfig.tokenPath) {
            authenticate("oauth2Client") {
                post {
                    val parameters: TokenExchangeParameters = call.tokenExchangeParameters()
                    val subjectTokenClaims = jwtTokenValidator.validate(parameters.subjectToken)
                    val audience: String = parameters.audience ?: parameters.resource
                    ?: throw OAuth2Exception(OAuth2Error.INVALID_REQUEST.appendDescription("audience or resource must be set"))
                    val token = jwtTokenIssuer.issueTokenFor("todo", subjectTokenClaims, audience)
                    call.respond(
                        OAuth2TokenResponse(
                            accessToken = token.serialize(),
                            expiresIn = token.expiresIn(),
                            scope = parameters.scope
                        )
                    )
                }
            }
        }
    }
}

private suspend fun ApplicationCall.tokenExchangeParameters(): TokenExchangeParameters = TokenExchangeParameters(this.receiveParameters())

fun SignedJWT.expiresIn(): Int =
    Duration.between(Instant.now(), this.jwtClaimsSet.expirationTime.toInstant()).seconds.toInt()

data class OAuth2Exception(val errorObject: ErrorObject? = null, val throwable: Throwable? = null) : RuntimeException(errorObject?.toString(), throwable)

// TODO actually validate request, is not validated until getter accessed
class TokenExchangeParameters(
    private val parameters: Parameters
) {
    val grantType: String =
        parameters["grant_type"]?.takeIf { it == "urn:ietf:params:oauth:grant-type:token-exchange" } ?: throw invalidParameter("grant_type")
    val subjectTokenType: String
        get() = parameters["subject_token_type"].takeIf { it == "urn:ietf:params:oauth:token-type:jwt" } ?: throw invalidParameter("subject_token_type")
    val subjectToken: String
        get() = parameters["subject_token"] ?: throw invalidParameter("subject_token")
    val resource: String?
        get() = parameters["resource"]
    val audience: String?
        get() = parameters["audience"]
    val scope: String?
        get() = parameters["scope"]

    private fun invalidParameter(name: String): RuntimeException = RuntimeException("invalid parameter $name=${parameters[name]}")
}
