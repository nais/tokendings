package io.nais.security.oauth2

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.databind.SerializationFeature
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.oauth2.sdk.ErrorObject
import com.nimbusds.oauth2.sdk.OAuth2Error
import io.ktor.application.ApplicationCall
import io.ktor.application.call
import io.ktor.application.install
import io.ktor.auth.Authentication
import io.ktor.features.CallLogging
import io.ktor.features.ContentNegotiation
import io.ktor.features.StatusPages
import io.ktor.http.HttpStatusCode
import io.ktor.http.Parameters
import io.ktor.http.auth.HttpAuthHeader
import io.ktor.jackson.jackson
import io.ktor.request.receiveParameters
import io.ktor.response.respond
import io.ktor.routing.get
import io.ktor.routing.post
import io.ktor.routing.route
import io.ktor.routing.routing
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.nais.security.oauth2.config.Configuration
import io.nais.security.oauth2.jwt.JwtTokenIssuer
import io.nais.security.oauth2.jwt.JwtTokenValidator
import org.slf4j.LoggerFactory
import org.slf4j.event.Level
import java.time.Duration
import java.time.Instant

private val log = LoggerFactory.getLogger("Main")
private val config = Configuration()

fun main() {
    TokenExchangeService().start()
}

class TokenExchangeService {

    companion object {
        const val wellKnownUri = "/.well-known/oauth-authorization-server"
        const val authorizationUri = "/authorization"
        const val tokenUri = "/token"
        const val jwksUri = "/jwks"
    }


    fun start() {
        val issuer = "http://localhost:${config.application.port}"
        val authorizationEndpoint = "$issuer$authorizationUri"
        val tokenEndpoint = "$issuer$tokenUri"
        val jwksEndpoint = "$issuer$jwksUri"

        val jwtTokenValidator = JwtTokenValidator()
        val jwtTokenIssuer = JwtTokenIssuer(issuer)

        embeddedServer(Netty, port = config.application.port) {

            // TODO: Exception handling with oauth2 errors
            install(StatusPages) {
                exception<Throwable> { cause ->
                    call.respond(HttpStatusCode.InternalServerError, OAuth2Error.SERVER_ERROR)
                    throw cause
                }
            }

            install(ContentNegotiation) {
                jackson {
                    enable(SerializationFeature.INDENT_OUTPUT)
                }
            }

            install(Authentication) {

            }

            install(CallLogging) {
                level = Level.INFO
            }
            routing {
                route("/.well-known/oauth-authorization-server") {
                    get {
                        call.respond(
                            WellKnown(
                                issuer = issuer,
                                authorizationEndpoint = authorizationEndpoint,
                                tokenEndpoint = tokenEndpoint,
                                jwksUri = jwksEndpoint
                            )
                        )
                    }
                }
                get("/jwks") {
                    call.respond(jwtTokenIssuer.publicJwkSet().toJSONObject())
                }
                route("/token") {
                    post {
                        val parameters: TokenExchangeParameters = call.tokenExchangeParameters()
                        val subjectTokenClaims = jwtTokenValidator.validate(parameters.subjectToken)
                        val audience: String = parameters.audience ?: parameters.resource
                        ?: throw OAuth2Exception(OAuth2Error.INVALID_REQUEST.appendDescription("audience or resource must be set"))
                        val token = jwtTokenIssuer.issueTokenFor(subjectTokenClaims, audience)
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
        }.start(wait = true)
    }

    private suspend fun ApplicationCall.tokenExchangeParameters(): TokenExchangeParameters {
        return TokenExchangeParameters(this.receiveParameters())
    }

    fun SignedJWT.expiresIn(): Int =
        Duration.between(Instant.now(), this.jwtClaimsSet.expirationTime.toInstant()).seconds.toInt()

    private fun HttpAuthHeader.getBlob(): String? = when {
        this is HttpAuthHeader.Single && authScheme.toLowerCase() in listOf("bearer") -> blob
        else -> null
    }

    data class OAuth2Exception(val errorObject: ErrorObject? = null, val throwable: Throwable? = null) :
        RuntimeException(errorObject?.toString(), throwable) {
    }

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

        private fun invalidParameter(name: String): RuntimeException = RuntimeException("invalid parameter ${name}=${parameters[name]}")
    }

    data class WellKnown(
        val issuer: String,
        @JsonProperty("authorization_endpoint")
        val authorizationEndpoint: String,
        @JsonProperty("token_endpoint")
        val tokenEndpoint: String,
        @JsonProperty("jwks_uri")
        val jwksUri: String,
        /*@JsonProperty("response_types_supported")
    val responseTypesSupported: List<String> = listOf("code"),*/
        @JsonProperty("grant_types_supported")
        val grantTypesSupported: List<String> = listOf("urn:ietf:params:oauth:grant-type:token-exchange"),
        @JsonProperty("token_endpoint_auth_methods_supported")
        val tokenEndpointAuthMethodsSupported: List<String> = listOf("client_secret_post", "client_secret_basic", "private_key_jwt"),
        @JsonProperty("token_endpoint_auth_signing_alg_values_supported")
        val tokenEndpointAuthSigningAlgValuesSupported: List<String> = listOf("RS256"),
        @JsonProperty("subject_types_supported")
        val subjectTypesSupported: List<String> = listOf("public")
        /* @JsonProperty("id_token_signing_alg_values_supported")
     val idTokenSigningAlgValuesSupported: List<String> = listOf("RS256")*/
    )

    @JsonInclude(JsonInclude.Include.NON_NULL)
    data class OAuth2TokenResponse(
        @JsonProperty("access_token")
        val accessToken: String,
        @JsonProperty("issued_token_type")
        val issuedTokenType: String = "urn:ietf:params:oauth:token-type:access_token",
        @JsonProperty("token_type")
        val tokenType: String = "Bearer",
        @JsonProperty("expires_in")
        val expiresIn: Int = 0,
        @JsonProperty("scope")
        val scope: String? = null,
        @JsonProperty("refresh_token")
        val refreshToken: String? = null
    )
}
