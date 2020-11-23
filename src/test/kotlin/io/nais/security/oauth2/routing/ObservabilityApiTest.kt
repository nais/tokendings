package io.nais.security.oauth2.routing

import io.ktor.http.HttpMethod.Companion.Get
import io.ktor.http.HttpStatusCode.Companion.InternalServerError
import io.ktor.http.HttpStatusCode.Companion.OK
import io.ktor.server.testing.withTestApplication
import io.ktor.server.testing.handleRequest
import io.ktor.util.KtorExperimentalAPI
import io.nais.security.oauth2.mock.mockConfig
import io.nais.security.oauth2.mock.withMockOAuth2Server
import io.nais.security.oauth2.tokenExchangeApp
import io.prometheus.client.CollectorRegistry
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Test

@KtorExperimentalAPI
internal class ObservabilityApiTest {

    @Test
    fun `call to isready should answer OK if database is responding`() {
        withMockOAuth2Server {
            val mockConfig = mockConfig(mockOAuth2Server = this, failHealthCheck = false)
            withTestApplication({
                tokenExchangeApp(mockConfig, DefaultRouting(mockConfig))
            }) {
                with(handleRequest(Get, "/internal/isready")) {
                    assertThat(response.status() == OK)
                }
            }
        }
    }

    @Test
    fun `call to isready should fail if database is not responding`() {
        withMockOAuth2Server {
            val mockConfig = mockConfig(mockOAuth2Server = this, failHealthCheck = true)
            withTestApplication({
                tokenExchangeApp(mockConfig, DefaultRouting(mockConfig))
            }) {
                with(handleRequest(Get, "/internal/isready")) {
                    assertThat(response.status() == InternalServerError)
                }
            }
        }
    }

    @AfterEach
    fun clearMetricsRegistry() =
        CollectorRegistry.defaultRegistry.clear()
}
