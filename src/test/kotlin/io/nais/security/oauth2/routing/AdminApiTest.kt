package io.nais.security.oauth2.routing

import io.ktor.http.HttpMethod.Companion.Get
import io.ktor.http.HttpHeaders.Authorization
import io.ktor.http.HttpStatusCode.Companion.Unauthorized
import io.ktor.server.testing.handleRequest
import io.ktor.server.testing.withTestApplication
import io.ktor.util.KtorExperimentalAPI
import io.nais.security.oauth2.mock.mockConfig
import io.nais.security.oauth2.mock.withMigratedDb
import io.nais.security.oauth2.mock.withMockOAuth2Server
import io.nais.security.oauth2.tokenExchangeApp
import io.prometheus.client.CollectorRegistry
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test

@KtorExperimentalAPI
internal class AdminApiTest {

    @AfterEach
    fun tearDown() {
        CollectorRegistry.defaultRegistry.clear()
    }

    @Test
    fun `admin endpoint responds with 401 if valid bearer auth not provided`() {
        withMockOAuth2Server {
            val mockConfig = mockConfig(this)
            withTestApplication({
                tokenExchangeApp(mockConfig, DefaultRouting(mockConfig))
            }) {
                with(handleRequest(Get, "/admin/clients")) {
                    assertThat(response.status()).isEqualTo(Unauthorized)
                }
            }
        }
    }

    @Test
    fun `admin endpoint responds with 401 if invalid bearer auth provided`() {
        withMockOAuth2Server {
            val mockConfig = mockConfig(this)
            withTestApplication({
                tokenExchangeApp(mockConfig, DefaultRouting(mockConfig))
            }) {
                with(
                    handleRequest(Get, "/admin/clients") {
                        addHeader(
                            Authorization,
                            "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
                                "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ." +
                                "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
                        )
                    }
                ) {
                    assertThat(response.status()).isEqualTo(Unauthorized)
                }
            }
        }
    }

    companion object {
        @BeforeAll
        @JvmStatic
        @Suppress("unused")
        fun initDb() {
            withMigratedDb {
                // just trigger db migration
            }
        }
    }
}
