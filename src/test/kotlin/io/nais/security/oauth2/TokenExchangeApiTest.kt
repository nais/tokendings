package io.nais.security.oauth2

import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.http.formUrlEncode
import io.ktor.server.testing.handleRequest
import io.ktor.server.testing.setBody
import io.ktor.server.testing.withTestApplication
import io.nais.security.oauth2.config.TokenIssuerProperties.Companion.wellKnownPath
import io.nais.security.oauth2.mock.MockClientRegistry
import io.nais.security.oauth2.mock.mockConfig
import io.nais.security.oauth2.mock.withMockOAuth2Server
import io.nais.security.oauth2.model.AccessPolicy
import no.nav.security.mock.oauth2.token.DefaultOAuth2TokenCallback
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach

import org.junit.jupiter.api.Test

internal class TokenExchangeApiTest {

    @BeforeEach
    fun setUp() {
    }

    @AfterEach
    fun tearDown() {
    }

    @Test
    fun test() {

        withMockOAuth2Server {
            val mockConfig = mockConfig(this)
            withTestApplication({
                tokenExchangeApp(mockConfig, DefaultRouting(mockConfig))
            }) {
                with(handleRequest(HttpMethod.Get, wellKnownPath)) {
                    assertThat(response.status()).isEqualTo(HttpStatusCode.OK)
                    println("response yeah: ${response.content}")
                }
            }
        }

        /*      withTestApplication({
                  tokenExchangeApp(config, DefaultRouting(config))
              }) {
                  with(handleRequest(HttpMethod.Get, TokenIssuerConfig.wellKnownPath)) {
                      assertEquals(HttpStatusCode.OK, response.status())
                      println("response yeah: ${response.content}" )
                  }
              }*/
    }

    @Test
    fun `successfull token exchange call with valid client and subject_token`() {

        withMockOAuth2Server {
            val mockConfig = mockConfig(this)
            val registry = (mockConfig.clientRegistry as MockClientRegistry)
            val client1 = registry.registerClientAndGenerateKeys("client1", AccessPolicy())
            val client2 = registry.registerClientAndGenerateKeys("client2",
                AccessPolicy(listOf("client1"))
            )
            val clientAssertion = registry.generateClientAssertionFor(client1.clientId).serialize()
            val subjectToken = this.issueToken("mock1", "someclientid", DefaultOAuth2TokenCallback()).serialize()

            withTestApplication({
                tokenExchangeApp(mockConfig, DefaultRouting(mockConfig))
            }) {
                with(handleRequest(HttpMethod.Post, "/token") {
                    addHeader(HttpHeaders.ContentType, ContentType.Application.FormUrlEncoded.toString())
                    setBody(
                        listOf(
                            "client_assertion_type" to "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                            "client_assertion" to clientAssertion,
                            "grant_type" to "urn:ietf:params:oauth:grant-type:token-exchange",
                            "audience" to client2.clientId,
                            "subject_token_type" to "urn:ietf:params:oauth:token-type:jwt",
                            "subject_token" to subjectToken
                        ).formUrlEncode()
                    )
                }) {

                    println("response yeah: ${response.content}")
                    assertThat(response.status()).isEqualTo(HttpStatusCode.OK)
                }
            }
        }
    }
}
