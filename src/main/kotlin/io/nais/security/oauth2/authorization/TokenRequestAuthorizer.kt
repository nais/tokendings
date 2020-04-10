package io.nais.security.oauth2.authorization

import com.nimbusds.oauth2.sdk.OAuth2Error
import io.ktor.http.Parameters
import io.nais.security.oauth2.authentication.ClientAuthenticationPrincipal
import io.nais.security.oauth2.authentication.ClientRegistry
import io.nais.security.oauth2.authentication.OAuth2Client
import io.nais.security.oauth2.model.GrantType
import io.nais.security.oauth2.model.OAuth2Exception
import io.nais.security.oauth2.model.OAuth2TokenExchangeRequest
import io.nais.security.oauth2.model.OAuth2TokenRequest
import io.nais.security.oauth2.model.TokenType
import mu.KotlinLogging
import org.slf4j.Logger

private val log: Logger = KotlinLogging.logger { }

interface TokenRequestAuthorizer<T : OAuth2TokenRequest> {

    fun supportsGrantType(grantType: String?): Boolean
    fun authorize(parameters: Parameters, principal: ClientAuthenticationPrincipal?): T
}

class TokenExchangeAuthorizer(private val clientRegistry: ClientRegistry) : TokenRequestAuthorizer<OAuth2TokenExchangeRequest> {

    override fun supportsGrantType(grantType: String?): Boolean = grantType == GrantType.TOKEN_EXCHANGE_GRANT

    override fun authorize(parameters: Parameters, principal: ClientAuthenticationPrincipal?): OAuth2TokenExchangeRequest {
        log.debug("authorize request with parameters=$parameters for principal=$principal")
        val tokenRequest: OAuth2TokenExchangeRequest = parameters.tokenExchangeRequest()
        val targetClient: OAuth2Client = clientRegistry.findClient(tokenRequest.audience)
            ?: throw OAuth2Exception(OAuth2Error.INVALID_REQUEST.setDescription("audience ${tokenRequest.audience} is invalid"))
        val authenticatedClient: OAuth2Client = principal?.oauth2Client
            ?: throw OAuth2Exception(OAuth2Error.INVALID_REQUEST.setDescription("client is not authenticated"))

        return when {
            targetClient.accessPolicyInbound.contains(authenticatedClient.clientId) -> tokenRequest
            else -> throw OAuth2Exception(
                    OAuth2Error.INVALID_REQUEST.setDescription(
                        "client ${authenticatedClient.clientId} is not authorized to invoke API with client_id=${targetClient.clientId}"
                    )
                )
        }
    }
}

private fun Parameters.tokenExchangeRequest(): OAuth2TokenExchangeRequest {
    return OAuth2TokenExchangeRequest(
        this.require("subject_token_type", TokenType.TOKEN_TYPE_JWT),
        this.require("subject_token"),
        this.require("audience"),
        this["resource"],
        this["scope"]
    )
}


@Throws(OAuth2Exception::class)
fun Parameters.require(name: String, requiredValue: String? = null): String =
    when {
        requiredValue != null -> {
            this[name]
                ?.takeIf { it == requiredValue }
                ?: throw OAuth2Exception(OAuth2Error.INVALID_REQUEST.setDescription("Parameter $name must be $requiredValue"))
        }
        else -> {
            this[name] ?: throw OAuth2Exception(OAuth2Error.INVALID_REQUEST.setDescription("Parameter $name missing"))
        }
    }
