package io.nais.security.oauth2.authentication

import com.nimbusds.jwt.SignedJWT
import com.nimbusds.oauth2.sdk.OAuth2Error
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod
import io.ktor.application.ApplicationCall
import io.ktor.application.call
import io.ktor.auth.Authentication
import io.ktor.auth.AuthenticationFailedCause
import io.ktor.auth.AuthenticationFunction
import io.ktor.auth.AuthenticationPipeline
import io.ktor.auth.AuthenticationProvider
import io.ktor.auth.Credential
import io.ktor.auth.Principal
import io.ktor.auth.UnauthorizedResponse
import io.ktor.http.Parameters
import io.ktor.request.receiveParameters
import io.ktor.response.respond
import io.nais.security.oauth2.model.OAuth2Exception

data class ClientAssertionCredential(val clientAssertionType: String, val clientAssertion: String) : Credential {
    val clientAuthenticationMethod: ClientAuthenticationMethod = ClientAuthenticationMethod.PRIVATE_KEY_JWT
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

class ClientAuthenticationProvider internal constructor(
    configuration: Configuration
) : AuthenticationProvider(configuration) {

    internal val authenticationFunction = configuration.authenticationFunction

    class Configuration internal constructor(name: String?) : AuthenticationProvider.Configuration(name) {

        internal var authenticationFunction: AuthenticationFunction<ClientAssertionCredential> = {
            throw NotImplementedError(
                "client_asssertion validate function is not specified. Use oauth2ClientAuth { validate { ... } } to fix."
            )
        }

        fun validate(body: suspend ApplicationCall.(Credential) -> Principal?) {
            authenticationFunction = body
        }
    }
}

/**
 * Installs OAuth2 Client Authentication mechanism
 */
fun Authentication.Configuration.oauth2ClientAuth(
    name: String? = null,
    configure: ClientAuthenticationProvider.Configuration.() -> Unit
) {
    val provider = ClientAuthenticationProvider(ClientAuthenticationProvider.Configuration(name).apply(configure))
    val authenticate = provider.authenticationFunction

    provider.pipeline.intercept(AuthenticationPipeline.RequestAuthentication) { context ->
        val credentials = call.receiveClientAuthenticationCredentials()
        val principal = credentials?.let { authenticate(call, it) }

        val cause = when {
            credentials == null -> AuthenticationFailedCause.NoCredentials
            principal == null -> AuthenticationFailedCause.InvalidCredentials
            else -> null
        }

        if (cause != null) {
            context.challenge(clientAuthenticationChallengeKey, cause) {
                call.respond(UnauthorizedResponse())
                it.complete()
            }
        }
        if (principal != null) {
            context.principal(principal)
        }
    }

    register(provider)
}

private suspend fun ApplicationCall.receiveClientAuthenticationCredentials(): ClientAssertionCredential? =
    clientAssertion(this.receiveParameters())

private fun clientAssertion(postParameters: Parameters?): ClientAssertionCredential? {
    val clientAssertionType = postParameters?.get("client_assertion_type")
    val clientAssertion = postParameters?.get("client_assertion")
    if (clientAssertionType != null && clientAssertion != null) {
        return ClientAssertionCredential(clientAssertionType, clientAssertion)
    }
    return null
}

private val clientAuthenticationChallengeKey: Any = "ClientAuth"
