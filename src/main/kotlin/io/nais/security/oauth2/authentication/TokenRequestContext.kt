package io.nais.security.oauth2.authentication

import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.jwt.proc.JWTClaimsSetVerifier
import com.nimbusds.oauth2.sdk.OAuth2Error
import io.ktor.http.Parameters
import io.ktor.server.application.ApplicationCall
import io.ktor.server.request.receiveParameters
import io.nais.security.oauth2.model.ClientId
import io.nais.security.oauth2.model.OAuth2Client
import io.nais.security.oauth2.model.OAuth2Exception
import io.nais.security.oauth2.model.OAuth2TokenRequest
import io.nais.security.oauth2.token.expiresIn
import io.nais.security.oauth2.token.toJwt
import io.nais.security.oauth2.token.verify
import io.opentelemetry.api.trace.SpanKind
import io.opentelemetry.instrumentation.annotations.WithSpan
import mu.KotlinLogging
import org.slf4j.MDC

typealias AcceptedAudience = Set<String>

private val log = KotlinLogging.logger { }

class TokenRequestContext private constructor(
    val oauth2Client: OAuth2Client,
    val oauth2TokenRequest: OAuth2TokenRequest,
) {
    data class ClientIDs(
        val client: String,
        val target: String,
    )

    class From(
        private val parameters: Parameters,
    ) {
        @WithSpan
        fun authenticateAndAuthorize(configure: TokenRequestConfig.Configuration.(ClientIDs) -> Unit): TokenRequestContext {
            val credential = credential()
            val config =
                TokenRequestConfig(
                    TokenRequestConfig.Configuration().apply {
                        val clientIds =
                            ClientIDs(
                                client = credential.clientId,
                                target = parameters.require("audience"),
                            )
                        configure(clientIds)
                    },
                )
            val client: OAuth2Client = authenticateClient(config, credential)
            val tokenRequest = authorizeTokenRequest(config, client)
            return TokenRequestContext(client, tokenRequest)
        }

        private fun credential(): ClientAssertionCredential =
            ClientAssertionCredential(
                parameters.require("client_assertion_type"),
                parameters.require("client_assertion"),
            ).also { client ->
                MDC.put("client_id", client.clientId)
            }

        @WithSpan
        private fun authenticateClient(
            config: TokenRequestConfig,
            clientAssertionCredential: ClientAssertionCredential,
        ): OAuth2Client =
            config.clientFinder
                .invoke(clientAssertionCredential)
                ?.also { oAuth2Client ->
                    val keyIds =
                        oAuth2Client.jwkSet.keys
                            .map { it.keyID }
                            .toList()
                    log.info("verify client_assertion for client_id=${oAuth2Client.clientId} with keyIds=$keyIds")
                    clientAssertionCredential.signedJWT.verify(
                        config.claimsVerifier(oAuth2Client.clientId),
                        oAuth2Client.jwkSet,
                    )
                    if (!clientAssertionCredential.signedJWT.isWithinMaxLifetime(config.clientAssertionMaxLifetime)) {
                        throw OAuth2Exception(
                            OAuth2Error.INVALID_CLIENT.setDescription(
                                "invalid client authentication for client_id=${clientAssertionCredential.clientId}," +
                                    " client assertion exceeded max lifetime (${config.clientAssertionMaxLifetime}s).",
                            ),
                        )
                    }
                } ?: throw OAuth2Exception(
                OAuth2Error.INVALID_CLIENT.setDescription(
                    "invalid client authentication for client_id=${clientAssertionCredential.clientId}, client not registered.",
                ),
            )

        @WithSpan
        private fun authorizeTokenRequest(
            config: TokenRequestConfig,
            client: OAuth2Client,
        ): OAuth2TokenRequest =
            config.authorizers
                .find { it.supportsGrantType(parameters["grant_type"]) }
                ?.authorize(parameters, client)
                ?: throw OAuth2Exception(
                    OAuth2Error.ACCESS_DENIED.setDescription(
                        "could not find authorizer for grant_type=${parameters["grant_type"]}",
                    ),
                )
    }
}

class TokenRequestConfig internal constructor(
    configuration: Configuration,
) {
    internal val clientFinder = configuration.clientFinder
    internal val claimsVerifier = configuration.claimsVerifier
    internal val authorizers = configuration.authorizers
    internal val clientAssertionMaxLifetime = configuration.clientAssertionMaxLifetime

    class Configuration {
        internal var clientFinder: (ClientAssertionCredential) -> OAuth2Client? = {
            throw NotImplementedError("clientFinder function not implemented")
        }
        internal var authorizers: List<TokenRequestAuthorizer<*>> = emptyList()

        internal lateinit var acceptedAudience: AcceptedAudience
        internal var claimsVerifier: (ClientId) -> JWTClaimsSetVerifier<SecurityContext?> = { clientId ->
            ClientAssertionJwtClaimsVerifier(
                acceptedAudience = acceptedAudience,
                expectedIssuer = clientId,
                expectedSubject = clientId,
            )
        }

        internal var clientAssertionMaxLifetime: Long = CLIENT_ASSERTION_MAX_LIFETIME
    }

    companion object {
        private const val CLIENT_ASSERTION_MAX_LIFETIME = 120L
    }
}

data class ClientAssertionCredential(
    val clientAssertionType: String,
    val clientAssertion: String,
) {
    val signedJWT: SignedJWT =
        when (clientAssertionType) {
            JWT_BEARER -> clientAssertion.toJwt()
            else -> throw OAuth2Exception(OAuth2Error.INVALID_CLIENT.appendDescription(": invalid client_assertion_type"))
        }
    val clientId =
        signedJWT.jwtClaimsSet?.subject
            ?: throw OAuth2Exception(OAuth2Error.INVALID_CLIENT.appendDescription(": sub must be present in assertion"))

    companion object {
        const val JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    }
}

private fun SignedJWT.isWithinMaxLifetime(lifetime: Long): Boolean = this.expiresIn() <= lifetime

@WithSpan(kind = SpanKind.CLIENT)
suspend fun ApplicationCall.receiveTokenRequestContext(block: TokenRequestContext.From.() -> TokenRequestContext): TokenRequestContext =
    block.invoke(TokenRequestContext.From(this.receiveParameters()))
