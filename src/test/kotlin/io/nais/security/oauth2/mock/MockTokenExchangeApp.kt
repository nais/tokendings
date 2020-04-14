package io.nais.security.oauth2.mock

import io.ktor.application.Application
import io.ktor.application.call
import io.ktor.request.receive
import io.ktor.response.respond
import io.ktor.routing.Routing
import io.ktor.routing.post
import io.ktor.routing.routing
import io.ktor.util.KtorExperimentalAPI
import io.nais.security.oauth2.DefaultRouting
import io.nais.security.oauth2.config.AppConfiguration
import io.nais.security.oauth2.server
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

            post("yolo") {
                call.respond(call.receive<String>())
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
