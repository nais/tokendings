package io.nais.security.oauth2.authentication

import com.nimbusds.oauth2.sdk.OAuth2Error
import io.ktor.http.Parameters
import io.nais.security.oauth2.model.GrantType
import io.nais.security.oauth2.model.OAuth2Client
import io.nais.security.oauth2.model.OAuth2ClientCredentialsTokenRequest
import io.nais.security.oauth2.model.OAuth2Exception
import io.nais.security.oauth2.model.OAuth2TokenExchangeRequest
import io.nais.security.oauth2.model.OAuth2TokenRequest
import io.nais.security.oauth2.model.SubjectTokenType
import io.opentelemetry.instrumentation.annotations.WithSpan
import mu.KotlinLogging
import org.slf4j.Logger

private val log: Logger = KotlinLogging.logger { }

interface TokenRequestAuthorizer<T : OAuth2TokenRequest> {
    fun supportsGrantType(grantType: String?): Boolean

    fun authorize(
        parameters: Parameters,
        oauth2Client: OAuth2Client?,
    ): T
}

class TokenExchangeRequestAuthorizer(
    private val targetClients: Map<String, OAuth2Client>,
) : TokenRequestAuthorizer<OAuth2TokenExchangeRequest> {
    override fun supportsGrantType(grantType: String?): Boolean = grantType == GrantType.TOKEN_EXCHANGE_GRANT

    @WithSpan
    override fun authorize(
        parameters: Parameters,
        oauth2Client: OAuth2Client?,
    ): OAuth2TokenExchangeRequest {
        log.debug("authorize request with parameters=$parameters for principal=$oauth2Client")
        val tokenRequest =
            OAuth2TokenExchangeRequest(
                parameters.require("subject_token_type", SubjectTokenType.TOKEN_TYPE_JWT),
                parameters.require("subject_token"),
                parameters.require("audience"),
                parameters["resource"],
                parameters["scope"],
            )

        val targetClient =
            targetClients[tokenRequest.audience]
                ?: throw OAuth2Exception(
                    OAuth2Error.INVALID_REQUEST.setDescription(
                        "token exchange audience ${tokenRequest.audience} is invalid",
                    ),
                )

        val authenticatedClient =
            oauth2Client
                ?: throw OAuth2Exception(
                    OAuth2Error.INVALID_REQUEST.setDescription("client is not authenticated"),
                )

        return when {
            targetClient.accessPolicyInbound.contains(authenticatedClient.clientId) -> tokenRequest
            else -> throw OAuth2Exception(
                OAuth2Error.INVALID_REQUEST.setDescription(
                    "client '${authenticatedClient.clientId}' is not authorized to get token with aud=${targetClient.clientId}",
                ),
            )
        }
    }
}

class ClientCredentialsRequestAuthorizer : TokenRequestAuthorizer<OAuth2ClientCredentialsTokenRequest> {
    override fun supportsGrantType(grantType: String?): Boolean = grantType == GrantType.CLIENT_CREDENTIALS_GRANT

    @WithSpan
    override fun authorize(
        parameters: Parameters,
        oauth2Client: OAuth2Client?,
    ): OAuth2ClientCredentialsTokenRequest {
        log.debug("authorize request with parameters=$parameters for principal=$oauth2Client")
        val tokenRequest =
            OAuth2ClientCredentialsTokenRequest(
                parameters.require("scope"),
            )
        val authenticatedClient: OAuth2Client =
            oauth2Client
                ?: throw OAuth2Exception(OAuth2Error.INVALID_REQUEST.setDescription("client is not authenticated"))

        return when {
            authenticatedClient.allowedScopes.contains(tokenRequest.scope) -> tokenRequest
            else -> throw OAuth2Exception(
                OAuth2Error.INVALID_REQUEST.setDescription(
                    "client '${authenticatedClient.clientId}' is not authorized to get token with aud=${tokenRequest.scope}",
                ),
            )
        }
    }
}
