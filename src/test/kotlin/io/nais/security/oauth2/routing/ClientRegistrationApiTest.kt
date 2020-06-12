package io.nais.security.oauth2.routing

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.oauth2.sdk.OAuth2Error
import io.kotest.matchers.shouldBe
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.server.testing.handleRequest
import io.ktor.server.testing.setBody
import io.ktor.server.testing.withTestApplication
import io.nais.security.oauth2.config.ClientRegistrationAuthProperties
import io.nais.security.oauth2.mock.MockApp
import io.nais.security.oauth2.mock.MockClientRegistry
import io.nais.security.oauth2.mock.mockConfig
import io.nais.security.oauth2.mock.withMockOAuth2Server
import io.nais.security.oauth2.model.ClientRegistrationRequest
import io.nais.security.oauth2.model.JsonWebKeys
import io.nais.security.oauth2.model.SoftwareStatement
import io.nais.security.oauth2.model.SoftwareStatementJwt
import io.nais.security.oauth2.token.sign
import io.nais.security.oauth2.utils.shouldBe
import io.nais.security.oauth2.utils.jwkSet
import no.nav.security.mock.oauth2.token.DefaultOAuth2TokenCallback
import org.intellij.lang.annotations.Language
import org.junit.jupiter.api.Test

internal class ClientRegistrationApiTest {

    @Test
    fun `401 on unauthorized requests`() {
        withMockOAuth2Server {
            val mockConfig = mockConfig(
                this, ClientRegistrationAuthProperties(
                    this.wellKnownUrl("mockaad").toString(),
                    emptyList(),
                    emptyMap(),
                    jwkSet()
                )
            )
            withTestApplication(MockApp(mockConfig)) {
                handleRequest(HttpMethod.Post, "registration/client").response.status() shouldBe HttpStatusCode.Unauthorized
            }
        }
    }

    @Test
    fun `401 on incorrect audience in bearer token`() {
        withMockOAuth2Server {
            val config = mockConfig(
                this,
                ClientRegistrationAuthProperties(
                    this.wellKnownUrl("mockaad").toString(),
                    listOf("correct_aud"),
                    emptyMap(),
                    jwkSet()
                )
            )
            val token = this.issueToken(
                "mockaad", "client1", DefaultOAuth2TokenCallback(
                    issuerId = "mockaad",
                    subject = "client1",
                    audience = "incorrect_aud"
                )
            ).serialize()
            withTestApplication(MockApp(config)) {
                handleRequest(HttpMethod.Post, "registration/client") {
                    addHeader(HttpHeaders.Authorization, "Bearer $token")
                }.apply {
                    response.status() shouldBe HttpStatusCode.Unauthorized
                }
            }
        }
    }

    @Test
    fun `successful client registration call with valid bearer token and signed software statement`() {
        withMockOAuth2Server {
            val signingKeySet = jwkSet()
            val config = mockConfig(
                this,
                ClientRegistrationAuthProperties(
                    this.wellKnownUrl("mockaad").toString(),
                    listOf("correct_aud"),
                    emptyMap(),
                    signingKeySet
                )
            )
            val token = this.issueToken(
                "mockaad", "client1", DefaultOAuth2TokenCallback(
                    issuerId = "mockaad",
                    subject = "client1",
                    audience = "correct_aud"
                )
            ).serialize()

            withTestApplication(MockApp(config)) {
                with(handleRequest(HttpMethod.Post, "registration/client") {
                    addHeader(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                    addHeader(HttpHeaders.Authorization, "Bearer $token")
                    setBody(
                        ClientRegistrationRequest(
                            "cluster1:ns1:client1",
                            JsonWebKeys(jwkSet()),
                            softwareStatementJwt(
                                SoftwareStatement(
                                    "cluster1:ns1:client1",
                                    listOf("cluster1:ns1:client2"),
                                    emptyList()
                                ),
                                signingKeySet.keys.first() as RSAKey
                            )
                        ).toJson()
                    )
                }) {
                    response.status() shouldBe HttpStatusCode.Created
                    config.clientRegistry.findClient("cluster1:ns1:client1")?.clientId shouldBe "cluster1:ns1:client1"
                }
            }
        }
    }

    @Test
    fun `client registration call with valid bearer token and invalid software statement content should fail`() {
        withMockOAuth2Server {
            val signingKeySet = jwkSet()
            val config = mockConfig(
                this,
                ClientRegistrationAuthProperties(
                    this.wellKnownUrl("mockaad").toString(),
                    listOf("correct_aud"),
                    emptyMap(),
                    signingKeySet
                )
            )
            val token = this.issueToken(
                "mockaad", "client1", DefaultOAuth2TokenCallback(
                    issuerId = "mockaad",
                    subject = "client1",
                    audience = "correct_aud"
                )
            ).serialize()

            @Language("JSON")
            val invalidSoftwareStatement: String = """
                {
                  "appId": "cluster:ns:app1",
                  "accessPolicyInbound": [
                    "cluster:ns:app2"
                  ],
                  "accessPolicyOutbound": null
                }
            """.trimIndent()

            withTestApplication(MockApp(config)) {
                with(handleRequest(HttpMethod.Post, "registration/client") {
                    addHeader(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                    addHeader(HttpHeaders.Authorization, "Bearer $token")
                    setBody(invalidSoftwareStatement)
                }) {
                    response.status() shouldBe HttpStatusCode.BadRequest
                    config.clientRegistry.findClient("cluster1:ns1:client1") shouldBe null
                }
            }
        }
    }

    @Test
    fun `client registration call with valid bearer token and invalid software statement signature should fail`() {
        withMockOAuth2Server {
            val signingKeySet = jwkSet()
            val config = mockConfig(
                this,
                ClientRegistrationAuthProperties(
                    this.wellKnownUrl("mockaad").toString(),
                    listOf("correct_aud"),
                    emptyMap(),
                    signingKeySet
                )
            )
            val token = this.issueToken(
                "mockaad", "client1", DefaultOAuth2TokenCallback(
                    issuerId = "mockaad",
                    subject = "client1",
                    audience = "correct_aud"
                )
            ).serialize()

            val invalidSoftwareStatement: String = ClientRegistrationRequest(
                "cluster1:ns1:client1",
                JsonWebKeys(jwkSet()),
                softwareStatementJwt(
                    SoftwareStatement(
                        "cluster1:ns1:client1",
                        listOf("cluster1:ns1:client2"),
                        emptyList()
                    ),
                    jwkSet().keys.first() as RSAKey
                )
            ).toJson()

            withTestApplication(MockApp(config)) {
                with(handleRequest(HttpMethod.Post, "registration/client") {
                    addHeader(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                    addHeader(HttpHeaders.Authorization, "Bearer $token")
                    setBody(invalidSoftwareStatement)
                }) {
                    response shouldBe OAuth2Error.INVALID_REQUEST
                    config.clientRegistry.findClient("cluster1:ns1:client1") shouldBe null
                }
            }
        }
    }

    @Test
    fun `client registration call with valid bearer token and empty JWKS should fail`() {
        withMockOAuth2Server {
            val signingKeySet = jwkSet()
            val config = mockConfig(
                this,
                ClientRegistrationAuthProperties(
                    this.wellKnownUrl("mockaad").toString(),
                    listOf("correct_aud"),
                    emptyMap(),
                    signingKeySet
                )
            )
            val token = this.issueToken(
                "mockaad", "client1", DefaultOAuth2TokenCallback(
                    issuerId = "mockaad",
                    subject = "client1",
                    audience = "correct_aud"
                )
            ).serialize()

            val invalidSoftwareStatement: String = ClientRegistrationRequest(
                "cluster1:ns1:client1",
                JsonWebKeys(JWKSet(emptyList())),
                softwareStatementJwt(
                    SoftwareStatement(
                        "cluster1:ns1:client1",
                        listOf("cluster1:ns1:client2"),
                        emptyList()
                    ),
                    signingKeySet.keys.first() as RSAKey
                )
            ).toJson()

            withTestApplication(MockApp(config)) {
                with(handleRequest(HttpMethod.Post, "registration/client") {
                    addHeader(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                    addHeader(HttpHeaders.Authorization, "Bearer $token")
                    setBody(invalidSoftwareStatement)
                }) {
                    response shouldBe OAuth2Error.INVALID_REQUEST
                    config.clientRegistry.findClient("cluster1:ns1:client1") shouldBe null
                }
            }
        }
    }

    @Test
    fun `delete non-existent client should return 204 No Content`() {
        withMockOAuth2Server {
            val config = mockConfig(
                this,
                ClientRegistrationAuthProperties(
                    this.wellKnownUrl("mockaad").toString(),
                    listOf("correct_aud"),
                    emptyMap(),
                    jwkSet()
                )
            )
            val token = this.issueToken(
                "mockaad", "client1", DefaultOAuth2TokenCallback(
                    issuerId = "mockaad",
                    subject = "client1",
                    audience = "correct_aud"
                )
            ).serialize()
            withTestApplication(MockApp(config)) {
                handleRequest(HttpMethod.Delete, "registration/client/yolo") {
                    addHeader(HttpHeaders.Authorization, "Bearer $token")
                }.apply {
                    response.status() shouldBe HttpStatusCode.NoContent
                    config.clientRegistry.findClient("yolo") shouldBe null
                }
            }
        }
    }

    @Test
    fun `delete existing client should return 204 No Content`() {
        withMockOAuth2Server {
            val config = mockConfig(
                this,
                ClientRegistrationAuthProperties(
                    this.wellKnownUrl("mockaad").toString(),
                    listOf("correct_aud"),
                    emptyMap(),
                    jwkSet()
                )
            )
            val client1 = config.clientRegistry.let { it as MockClientRegistry }.register("client1")
            config.clientRegistry.findClient(client1.clientId) shouldBe client1
            val token = this.issueToken(
                "mockaad", "client1", DefaultOAuth2TokenCallback(
                    issuerId = "mockaad",
                    subject = "client1",
                    audience = "correct_aud"
                )
            ).serialize()
            withTestApplication(MockApp(config)) {
                handleRequest(HttpMethod.Delete, "registration/client/${client1.clientId}") {
                    addHeader(HttpHeaders.Authorization, "Bearer $token")
                }.apply {
                    response.status() shouldBe HttpStatusCode.NoContent
                    config.clientRegistry.findClient(client1.clientId) shouldBe null
                }
            }
        }
    }

    private fun softwareStatementJwt(softwareStatement: SoftwareStatement, rsaKey: RSAKey): SoftwareStatementJwt =
        JWTClaimsSet.Builder()
            .claim("appId", softwareStatement.appId)
            .claim("accessPolicyInbound", softwareStatement.accessPolicyInbound)
            .claim("accessPolicyOutbound", softwareStatement.accessPolicyOutbound)
            .build()
            .sign(rsaKey)
            .serialize()
}
