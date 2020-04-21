package io.nais.security.oauth2.mock

import com.nimbusds.jose.jwk.source.RemoteJWKSet
import com.nimbusds.jose.proc.SecurityContext
import io.ktor.application.Application
import io.ktor.application.call
import io.ktor.http.HttpStatusCode
import io.ktor.request.receive
import io.ktor.response.respond
import io.ktor.routing.Routing
import io.ktor.routing.get
import io.ktor.routing.post
import io.ktor.routing.route
import io.ktor.routing.routing
import io.ktor.util.KtorExperimentalAPI
import io.nais.security.oauth2.config.AppConfiguration
import io.nais.security.oauth2.config.AuthorizationServerProperties
import io.nais.security.oauth2.model.ClientId
import io.nais.security.oauth2.model.GrantType
import io.nais.security.oauth2.model.JsonWebKeys
import io.nais.security.oauth2.model.OAuth2Client
import io.nais.security.oauth2.routing.DefaultRouting
import io.nais.security.oauth2.server
import io.nais.security.oauth2.token.JwtTokenProvider.Companion.generateJWKSet
import mu.KotlinLogging
import no.nav.security.mock.oauth2.MockOAuth2Server
import no.nav.security.mock.oauth2.OAuth2Config
import java.net.URL

val log = KotlinLogging.logger { }

// TODO: remove, keep for now for local integration testing.
private val adminJwksUrl = "http://localhost:3000/jwks"
private val adminClientId = "the_best_cluster_in_the_finstadjordet:nais:jwker"
private val enableRemoteAdminClient = false

@KtorExperimentalAPI
fun main() {
    val mockOAuth2Server: MockOAuth2Server = startMockOAuth2Server()
    val config: AppConfiguration = mockConfig(mockOAuth2Server)
    if (enableRemoteAdminClient) {
        // will fail if remote admin client server is not started before this one
        config.clientRegistry.registerClient(remoteAdminClient(config.authorizationServerProperties))
    }
    server(
        config,
        MockApiRouting(config)
    ).start(wait = true)
}

fun remoteAdminClient(authorizationServerProperties: AuthorizationServerProperties): OAuth2Client =
    OAuth2Client(
        clientId = adminClientId,
        jwks = JsonWebKeys(RemoteJWKSet<SecurityContext?>(URL(adminJwksUrl)).cachedJWKSet),
        allowedScopes = listOf(authorizationServerProperties.clientRegistrationUrl()),
        allowedGrantTypes = listOf(GrantType.CLIENT_CREDENTIALS_GRANT)
    )

internal class MockApiRouting(private val config: AppConfiguration) : DefaultRouting(config) {
    override fun apiRouting(application: Application): Routing {
        return application.routing {
            super.apiRouting(application)

            route("/admin") {
                post("/client") {
                    val adminClient: AdminClient = call.receive()
                    val oAuth2Client = OAuth2Client(
                        clientId = adminClient.clientId,
                        jwks = adminClient.jwks ?: JsonWebKeys(generateJWKSet("generated-for-${adminClient.clientId}", 2048)),
                        allowedScopes = listOf(config.authorizationServerProperties.clientRegistrationUrl()),
                        allowedGrantTypes = listOf(GrantType.CLIENT_CREDENTIALS_GRANT)
                    )
                    config.clientRegistry.registerClient(oAuth2Client)
                    call.respond(HttpStatusCode.Created)
                }

                get("/client/{clientId}") {
                    val clientId = call.parameters["clientId"]
                    call.respond(config.clientRegistry.findClient(clientId!!)!!)
                }

                get("/client/{clientId}/assertion") {
                    val clientId = call.parameters["clientId"]
                    val signedJWT = clientId?.let {
                        (config.clientRegistry as MockClientRegistry).generateClientAssertionFor(it)
                    }
                    call.respond(signedJWT?.serialize() ?: HttpStatusCode.NotFound)
                }
            }
        }
    }

    data class AdminClient(
        val clientId: ClientId,
        val jwks: JsonWebKeys?
    )
}

private fun startMockOAuth2Server(): MockOAuth2Server =
    MockOAuth2Server(
        OAuth2Config(
            interactiveLogin = true
        )
    ).apply {
        this.start(1111)
    }
