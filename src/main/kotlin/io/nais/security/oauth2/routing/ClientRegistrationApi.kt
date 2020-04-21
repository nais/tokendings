package io.nais.security.oauth2.routing

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.oauth2.sdk.OAuth2Error
import io.ktor.application.call
import io.ktor.auth.authenticate
import io.ktor.auth.jwt.JWTPrincipal
import io.ktor.auth.principal
import io.ktor.http.HttpStatusCode
import io.ktor.request.receive
import io.ktor.response.respond
import io.ktor.routing.Route
import io.ktor.routing.delete
import io.ktor.routing.post
import io.ktor.routing.route
import io.nais.security.oauth2.config.AppConfiguration
import io.nais.security.oauth2.model.AccessPolicy
import io.nais.security.oauth2.model.ClientRegistration
import io.nais.security.oauth2.model.ClientRegistrationRequest
import io.nais.security.oauth2.model.GrantType
import io.nais.security.oauth2.model.OAuth2Client
import io.nais.security.oauth2.model.OAuth2Exception
import io.nais.security.oauth2.model.verifySoftwareStatement

internal fun Route.clientRegistrationApi(config: AppConfiguration) {

    route("/registration") {
        authenticate("BEARER_TOKEN") {
            post("/client") {
                val adminClient = call.principal<JWTPrincipal>()?.payload?.subject
                    ?.let { config.clientRegistry.findClient(it) }
                    ?: throw OAuth2Exception(OAuth2Error.INVALID_CLIENT)

                val request: ClientRegistrationRequest = call.receive(ClientRegistrationRequest::class)
                val clientToRegister: OAuth2Client = mapRequestToOAuth2Client(request, adminClient.jwkSet)
                config.clientRegistry.registerClient(clientToRegister)

                call.respond(
                    HttpStatusCode.Created, ClientRegistration(
                        clientToRegister.clientId,
                        clientToRegister.jwks,
                        request.softwareStatement,
                        clientToRegister.allowedGrantTypes,
                        "private_key_jwt"
                    )
                )
            }
            delete("/client/{clientId}") {
                val clientId = call.parameters["clientId"]
                if (clientId != null) {
                    config.clientRegistry.deleteClient(clientId)
                    call.respond(HttpStatusCode.NoContent)
                }
                call.respond(HttpStatusCode.BadRequest, "clientId not found")
            }
        }
    }
}

private fun mapRequestToOAuth2Client(request: ClientRegistrationRequest, jwkSet: JWKSet): OAuth2Client {
    val softwareStatement = request.verifySoftwareStatement(jwkSet)
    return OAuth2Client(
        softwareStatement.appId,
        request.jwks,
        AccessPolicy(softwareStatement.accessPolicyInbound),
        AccessPolicy(softwareStatement.accessPolicyOutbound),
        emptyList(),
        listOf(GrantType.TOKEN_EXCHANGE_GRANT)
    )
}
