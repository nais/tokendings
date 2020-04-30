package io.nais.security.oauth2.mock

import io.ktor.application.Application
import io.ktor.application.call
import io.ktor.client.request.get
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
import io.nais.security.oauth2.config.ClientReqistrationAuthProperties
import io.nais.security.oauth2.defaultHttpClient
import io.nais.security.oauth2.model.ClientId
import io.nais.security.oauth2.model.GrantType
import io.nais.security.oauth2.model.JsonWebKeys
import io.nais.security.oauth2.model.OAuth2Client
import io.nais.security.oauth2.routing.DefaultRouting
import io.nais.security.oauth2.server
import io.nais.security.oauth2.token.JwtTokenProvider.Companion.generateJWKSet
import kotlinx.coroutines.runBlocking
import mu.KotlinLogging
import no.nav.security.mock.oauth2.MockOAuth2Server
import no.nav.security.mock.oauth2.OAuth2Config

val log = KotlinLogging.logger { }

internal object MockAdminClientProperties {
    const val adminClientPort = 2222
    const val adminJwksUrl = "http://localhost:$adminClientPort/jwks"
    const val adminClientId = "mock:nais:jwker"
}

@KtorExperimentalAPI
fun main() {
    val mockOAuth2Server: MockOAuth2Server = startMockOAuth2Server()

    val clientRegistrationAuthProps = ClientReqistrationAuthProperties(
        mockOAuth2Server.wellKnownUrl("/aadmock").toString(),
        listOf("tokendings")
    )

    val config: AppConfiguration = mockConfig(mockOAuth2Server, clientRegistrationAuthProps)

    server(
        config,
        MockApiRouting(config)
    ).start(wait = true)
}

internal class MockApiRouting(private val config: AppConfiguration) : DefaultRouting(config) {
    override fun apiRouting(application: Application): Routing {
        return application.routing {
            super.apiRouting(application)

            route("/admin") {
                post("/client") {
                    val adminClient: AdminClient = call.receive()
                    val jwks: JsonWebKeys = when {
                        adminClient.jwks != null -> adminClient.jwks
                        adminClient.jwks_uri != null ->
                            runBlocking {
                                defaultHttpClient.get<JsonWebKeys>(adminClient.jwks_uri)
                            }
                        else -> JsonWebKeys(generateJWKSet("generated-for-${adminClient.clientId}", 2048))
                    }
                    val oAuth2Client = OAuth2Client(
                        clientId = adminClient.clientId,
                        jwks = jwks,
                        allowedScopes = listOf(config.authorizationServerProperties.clientRegistrationUrl()),
                        allowedGrantTypes = listOf(GrantType.CLIENT_CREDENTIALS_GRANT)
                    )
                    config.clientRegistry.registerClient(oAuth2Client)
                    call.respond(HttpStatusCode.Created)
                }

                get("/client/{clientId}") {
                    val clientId = call.parameters["clientId"]
                    val client = clientId?.let {
                        config.clientRegistry.findClient(it)
                    }
                    call.respond(client ?: HttpStatusCode.NotFound)
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
        val jwks: JsonWebKeys?,
        val jwks_uri: String?
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
