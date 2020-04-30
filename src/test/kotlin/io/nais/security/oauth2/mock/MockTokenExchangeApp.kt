package io.nais.security.oauth2.mock

import io.ktor.util.KtorExperimentalAPI
import io.nais.security.oauth2.config.AppConfiguration
import io.nais.security.oauth2.config.ClientReqistrationAuthProperties
import io.nais.security.oauth2.config.authenticationPropertiesFromEnvironment
import io.nais.security.oauth2.routing.DefaultRouting
import io.nais.security.oauth2.server
import mu.KotlinLogging
import no.nav.security.mock.oauth2.MockOAuth2Server
import no.nav.security.mock.oauth2.OAuth2Config

val log = KotlinLogging.logger { }


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
        DefaultRouting(config)
    ).start(wait = true)
}

private fun startMockOAuth2Server(): MockOAuth2Server =
    MockOAuth2Server(
        OAuth2Config(
            interactiveLogin = true
        )
    ).apply {
        this.start(1111)
    }
