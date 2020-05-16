package io.nais.security.oauth2.authentication

import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier
import com.nimbusds.oauth2.sdk.OAuth2Error
import io.ktor.application.ApplicationCall
import io.ktor.auth.Credential
import io.ktor.http.Parameters
import io.ktor.request.receiveParameters
import io.nais.security.oauth2.model.OAuth2Client
import io.nais.security.oauth2.model.OAuth2Exception
import io.nais.security.oauth2.model.OAuth2TokenRequest
import io.nais.security.oauth2.token.verify

typealias TokenEndpointUrl = String

class TokenRequestContext private constructor(
    val oauth2Client: OAuth2Client,
    val oauth2TokenRequest: OAuth2TokenRequest
) {

    class From(private val tokenEndpointUrl: TokenEndpointUrl, private val parameters: Parameters) {

        fun authenticateAndAuthorize(configure: TokenRequestConfig.Configuration.() -> Unit): TokenRequestContext {
            val config = TokenRequestConfig(TokenRequestConfig.Configuration().apply(configure))
            val credential = credential()
            val client: OAuth2Client = authenticateClient(config, credential)
            val tokenRequest = authorizeTokenRequest(config, client)
            return TokenRequestContext(client, tokenRequest)
        }

        private fun credential(): ClientAssertionCredential =
            ClientAssertionCredential(
                parameters.require("client_assertion_type"),
                parameters.require("client_assertion")
            )

        /**
         * Jwt Bearer token for client authentication: https://tools.ietf.org/html/draft-ietf-oauth-jwt-bearer-12
         * Threats: https://tools.ietf.org/html/draft-ietf-oauth-assertions-18#section-8.2
         *
         * Consider using jti and iat/exp in token to protect against replay attacks
         */
        private fun authenticateClient(config: TokenRequestConfig, clientAssertionCredential: ClientAssertionCredential): OAuth2Client =
            config.clientFinder.invoke(clientAssertionCredential)
                ?.also {
                    clientAssertionCredential.signedJWT.verify(
                        config.claimsVerifier.invoke(Pair(it, tokenEndpointUrl)),
                        it.jwkSet
                    )
                } ?: throw OAuth2Exception(
                OAuth2Error.INVALID_CLIENT.setDescription(
                    "invalid client authentication for client_id=${clientAssertionCredential.clientId}, client not registered."
                )
            )

        private fun authorizeTokenRequest(config: TokenRequestConfig, client: OAuth2Client): OAuth2TokenRequest =
            config.authorizers.find { it.supportsGrantType(parameters["grant_type"]) }
                ?.authorize(parameters, client)
                ?: throw OAuth2Exception(
                    OAuth2Error.ACCESS_DENIED.setDescription("could not find authorizer for grant_type=${parameters["grant_type"]}")
                )
    }
}

class TokenRequestConfig internal constructor(
    configuration: Configuration
) {
    internal val clientFinder = configuration.clientFinder
    internal val claimsVerifier = configuration.claimsVerifier
    internal val authorizers = configuration.authorizers

    class Configuration {
        internal var clientFinder: (ClientAssertionCredential) -> OAuth2Client? = {
            throw NotImplementedError("clientFinder function not implemented")
        }
        internal var authorizers: List<TokenRequestAuthorizer<*>> = emptyList()

        internal var claimsVerifier: (Pair<OAuth2Client, TokenEndpointUrl>) -> DefaultJWTClaimsVerifier<SecurityContext?> = {
            DefaultJWTClaimsVerifier(
                JWTClaimsSet.Builder()
                    .issuer(it.first.clientId)
                    .subject(it.first.clientId)
                    .audience(it.second)
                    .build(),
                HashSet(listOf("sub", "iss", "aud", "iat", "exp", "jti"))
            )
        }
    }
}

data class ClientAssertionCredential(val clientAssertionType: String, val clientAssertion: String) : Credential {
    val signedJWT: SignedJWT = when (clientAssertionType) {
        JWT_BEARER -> {
            SignedJWT.parse(clientAssertion)
        }
        else -> throw OAuth2Exception(OAuth2Error.INVALID_CLIENT.appendDescription(": invalid client_assertion_type"))
    }
    val clientId = signedJWT.jwtClaimsSet?.subject
        ?: throw OAuth2Exception(OAuth2Error.INVALID_CLIENT.appendDescription(": sub must be present in assertion"))

    companion object {
        const val JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    }
}

suspend fun ApplicationCall.receiveTokenRequestContext(
    tokenEndpointUrl: TokenEndpointUrl,
    block: TokenRequestContext.From.() -> TokenRequestContext
): TokenRequestContext = tokenRequestContext(tokenEndpointUrl, this.receiveParameters(), block)

internal fun tokenRequestContext(
    tokenEndpointUrl: TokenEndpointUrl,
    parameters: Parameters,
    block: TokenRequestContext.From.() -> TokenRequestContext
): TokenRequestContext =
    block.invoke(TokenRequestContext.From(tokenEndpointUrl, parameters))
