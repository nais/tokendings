package io.nais.security.oauth2.routing

import com.nimbusds.oauth2.sdk.OAuth2Error
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.call
import io.ktor.server.auth.authenticate
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.delete
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.route
import io.nais.security.oauth2.authentication.BearerTokenAuth
import io.nais.security.oauth2.config.AppConfiguration
import io.nais.security.oauth2.model.AccessPolicy
import io.nais.security.oauth2.model.ClientRegistration
import io.nais.security.oauth2.model.ClientRegistrationRequest
import io.nais.security.oauth2.model.GrantType
import io.nais.security.oauth2.model.OAuth2Client
import io.nais.security.oauth2.model.OAuth2Exception
import io.nais.security.oauth2.model.verifySoftwareStatement
import io.opentelemetry.instrumentation.annotations.WithSpan

@WithSpan
internal fun Route.clientRegistrationApi(config: AppConfiguration) {
    authenticate(BearerTokenAuth.CLIENT_REGISTRATION_AUTH) {
        route("/registration/client") {
            post {
                val request: ClientRegistrationRequest = call.receive(ClientRegistrationRequest::class).validate()
                val acceptedSignatureKeys = config.clientRegistrationAuthProperties.softwareStatementJwks
                val softwareStatement = request.verifySoftwareStatement(acceptedSignatureKeys)

                val grantTypes: List<String> = when {
                    request.grantTypes.isEmpty() -> listOf(GrantType.TOKEN_EXCHANGE_GRANT)
                    else -> request.grantTypes
                }
                val clientToRegister = OAuth2Client(
                    softwareStatement.appId,
                    request.jwks,
                    AccessPolicy(softwareStatement.accessPolicyInbound),
                    AccessPolicy(softwareStatement.accessPolicyOutbound),
                    request.scopes,
                    grantTypes
                )
                config.clientRegistry.registerClient(clientToRegister)
                call.respond(
                    HttpStatusCode.Created,
                    ClientRegistration(
                        clientToRegister.clientId,
                        clientToRegister.jwks,
                        request.softwareStatementJwt,
                        clientToRegister.allowedGrantTypes,
                        "private_key_jwt"
                    )
                )
            }
            delete("/{clientId}") {
                call.parameters["clientId"]?.let { clientId ->
                    config.clientRegistry.deleteClient(clientId)
                    call.respond(HttpStatusCode.NoContent)
                }
            }
            get {
                call.respond(config.clientRegistry.findAll())
            }
            get("/{clientId}") {
                val client: OAuth2Client? = call.parameters["clientId"]
                    ?.let { config.clientRegistry.findClient(it) }
                when (client) {
                    null -> call.respond(HttpStatusCode.NotFound, "client not found")
                    else -> call.respond(client)
                }
            }
        }
    }
}

private fun ClientRegistrationRequest.validate(): ClientRegistrationRequest {
    require(this.jwks.keys.isNotEmpty()) {
        throw OAuth2Exception(OAuth2Error.INVALID_REQUEST.setDescription("empty JWKS not allowed"))
    }
    return this
}
