package io.nais.security.oauth2.mock

import io.ktor.application.Application
import io.ktor.application.call
import io.ktor.http.HttpStatusCode
import io.ktor.response.respond
import io.ktor.routing.Routing
import io.ktor.routing.get
import io.ktor.routing.routing
import io.ktor.util.KtorExperimentalAPI
import io.nais.security.oauth2.DefaultRouting
import io.nais.security.oauth2.config.AppConfiguration
import io.nais.security.oauth2.model.JsonWebKeySet
import io.nais.security.oauth2.model.OAuth2Client
import io.nais.security.oauth2.server
import io.nais.security.oauth2.token.JwtTokenProvider.Companion.generateJWKSet
import mu.KotlinLogging
import no.nav.security.mock.oauth2.MockOAuth2Server
import no.nav.security.mock.oauth2.OAuth2Config

val log = KotlinLogging.logger { }

@KtorExperimentalAPI
fun main() {
    val mockOAuth2Server: MockOAuth2Server = startMockOAuth2Server()
    val config: AppConfiguration = mockConfig(mockOAuth2Server)
    server(
        config,
        MockApiRouting(config)
    ).start(wait = true)
}

class MockApiRouting(private val config: AppConfiguration) : DefaultRouting(config) {
    override fun apiRouting(application: Application): Routing {
        return application.routing {
            super.apiRouting(application)
            clientRegistrationApi(config)

            get("register") {
                // val store = ClientRegistrationStore(dataSource(DatabaseConfig()))
                call.request.queryParameters["client_id"]?.let {
                    config.clientRegistry.registerClient(OAuth2Client(it, JsonWebKeySet(generateJWKSet("tt", 2048))))
                }

                call.respond( // store.findAllClientRegistrations()!!)
                    config.clientRegistry.findAll()
                )
            }
            get("delete") {
                // val store = ClientRegistrationStore(dataSource(DatabaseConfig()))
                call.request.queryParameters["client_id"]?.let {
                    config.clientRegistry.deleteClient(it)
                }

                call.respond( // store.findAllClientRegistrations()!!)
                    config.clientRegistry.findAll()
                )
            }
            get("find") {
                val client = call.request.queryParameters["client_id"]?.let {
                    config.clientRegistry.findClient(it)
                }
                client?.let { call.respond(it) } ?: call.respond(HttpStatusCode.NotFound, "client not found")
            }
        }
    }
}

private fun startMockOAuth2Server(): MockOAuth2Server =
    MockOAuth2Server(
        OAuth2Config(
            interactiveLogin = true
        )
    ).apply {
        this.start(1111)
    }
