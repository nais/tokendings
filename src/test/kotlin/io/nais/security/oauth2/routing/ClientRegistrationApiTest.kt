package io.nais.security.oauth2.routing

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.oauth2.sdk.OAuth2Error
import io.kotest.matchers.shouldBe
import io.ktor.client.request.delete
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.testing.testApplication
import io.nais.security.oauth2.authentication.BearerTokenAuth
import io.nais.security.oauth2.config.ClientRegistrationAuthProperties
import io.nais.security.oauth2.mock.MockClientRegistry
import io.nais.security.oauth2.mock.mockConfig
import io.nais.security.oauth2.mock.withMockOAuth2Server
import io.nais.security.oauth2.model.ClientRegistrationRequest
import io.nais.security.oauth2.model.JsonWebKeys
import io.nais.security.oauth2.model.SoftwareStatement
import io.nais.security.oauth2.model.SoftwareStatementJwt
import io.nais.security.oauth2.token.sign
import io.nais.security.oauth2.tokenExchangeApp
import io.nais.security.oauth2.utils.jwkSet
import io.nais.security.oauth2.utils.shouldBeObject
import io.prometheus.client.CollectorRegistry
import no.nav.security.mock.oauth2.MockOAuth2Server
import no.nav.security.mock.oauth2.token.DefaultOAuth2TokenCallback
import org.intellij.lang.annotations.Language
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Test

internal class ClientRegistrationApiTest {

    @AfterEach
    fun tearDown() {
        CollectorRegistry.defaultRegistry.clear()
    }

    @Test
    fun `401 on unauthorized requests`() {
        withMockOAuth2Server {
            val config = mockConfig(
                this,
                ClientRegistrationAuthProperties(
                    identityProviderWellKnownUrl = this.wellKnownUrl("mockaad").toString(),
                    acceptedAudience = emptyList(),
                    softwareStatementJwks = jwkSet()
                )
            )
            testApplication {
                application { tokenExchangeApp(config, DefaultRouting(config)) }
                client.post("registration/client").status shouldBe HttpStatusCode.Unauthorized
            }
        }
    }

    @Test
    fun `401 on incorrect audience in bearer token`() {
        withMockOAuth2Server {
            val config = mockConfig(
                this,
                ClientRegistrationAuthProperties(
                    identityProviderWellKnownUrl = this.wellKnownUrl("mockaad").toString(),
                    acceptedAudience = listOf("correct_aud"),
                    softwareStatementJwks = jwkSet()
                )
            )
            val token = this.issueToken(
                "mockaad",
                "client1",
                DefaultOAuth2TokenCallback(
                    issuerId = "mockaad",
                    subject = "client1",
                    audience = listOf("incorrect_aud"),
                    claims = mapOf("roles" to BearerTokenAuth.ACCEPTED_ROLES_CLAIM_VALUE)
                )
            ).serialize()
            testApplication {
                application { tokenExchangeApp(config, DefaultRouting(config)) }
                client.post("registration/client") {
                    header(HttpHeaders.Authorization, "Bearer $token")
                }.status shouldBe HttpStatusCode.Unauthorized
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
                    identityProviderWellKnownUrl = this.wellKnownUrl("mockaad").toString(),
                    acceptedAudience = listOf("correct_aud"),
                    softwareStatementJwks = signingKeySet
                )
            )
            val token = this.issueValidToken("client1")

            testApplication {
                application { tokenExchangeApp(config, DefaultRouting(config)) }
                client.post("registration/client") {
                    header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                    header(HttpHeaders.Authorization, "Bearer $token")
                    setBody(
                        ClientRegistrationRequest(
                            clientName = "cluster1:ns1:client1",
                            jwks = JsonWebKeys(jwkSet()),
                            softwareStatementJwt = softwareStatementJwt(
                                SoftwareStatement(
                                    appId = "cluster1:ns1:client1",
                                    accessPolicyInbound = listOf("cluster1:ns1:client2"),
                                    accessPolicyOutbound = emptyList()
                                ),
                                signingKeySet.keys.first() as RSAKey
                            )
                        ).toJson()
                    )
                }.status shouldBe HttpStatusCode.Created
                config.clientRegistry.findClient("cluster1:ns1:client1")?.clientId shouldBe "cluster1:ns1:client1"
            }
        }
    }

    @Test
    fun `client registration call with valid bearer token missing required claim roles should fail`() {
        withMockOAuth2Server {
            val signingKeySet = jwkSet()
            val config = mockConfig(
                this,
                ClientRegistrationAuthProperties(
                    identityProviderWellKnownUrl = this.wellKnownUrl("mockaad").toString(),
                    acceptedAudience = listOf("correct_aud"),
                    softwareStatementJwks = signingKeySet
                )
            )
            val token = this.issueToken(
                "mockaad",
                "client1",
                DefaultOAuth2TokenCallback(
                    issuerId = "mockaad",
                    subject = "client1",
                    audience = listOf("correct_aud")
                )
            ).serialize()

            testApplication {
                application { tokenExchangeApp(config, DefaultRouting(config)) }
                client.post("registration/client") {
                    header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                    header(HttpHeaders.Authorization, "Bearer $token")
                    setBody(
                        ClientRegistrationRequest(
                            clientName = "cluster1:ns1:client1",
                            jwks = JsonWebKeys(jwkSet()),
                            softwareStatementJwt = softwareStatementJwt(
                                SoftwareStatement(
                                    appId = "cluster1:ns1:client1",
                                    accessPolicyInbound = listOf("cluster1:ns1:client2"),
                                    accessPolicyOutbound = emptyList()
                                ),
                                signingKeySet.keys.first() as RSAKey
                            )
                        ).toJson()
                    )
                }.status shouldBe HttpStatusCode.Unauthorized
            }
        }
    }

    @Test
    fun `client registration call with valid bearer token with incorrect roles claim value should fail`() {
        withMockOAuth2Server {
            val signingKeySet = jwkSet()
            val config = mockConfig(
                this,
                ClientRegistrationAuthProperties(
                    identityProviderWellKnownUrl = this.wellKnownUrl("mockaad").toString(),
                    acceptedAudience = listOf("correct_aud"),
                    softwareStatementJwks = signingKeySet
                )
            )
            val token = this.issueToken(
                "mockaad",
                "client1",
                DefaultOAuth2TokenCallback(
                    issuerId = "mockaad",
                    subject = "client1",
                    audience = listOf("correct_aud"),
                    claims = mapOf("roles" to listOf("not_accepted"))
                )
            ).serialize()

            testApplication {
                application { tokenExchangeApp(config, DefaultRouting(config)) }
                client.post("registration/client") {
                    header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                    header(HttpHeaders.Authorization, "Bearer $token")
                    setBody(
                        ClientRegistrationRequest(
                            clientName = "cluster1:ns1:client1",
                            jwks = JsonWebKeys(jwkSet()),
                            softwareStatementJwt = softwareStatementJwt(
                                SoftwareStatement(
                                    appId = "cluster1:ns1:client1",
                                    accessPolicyInbound = listOf("cluster1:ns1:client2"),
                                    accessPolicyOutbound = emptyList()
                                ),
                                signingKeySet.keys.first() as RSAKey
                            )
                        ).toJson()
                    )
                }.status shouldBe HttpStatusCode.Unauthorized
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
                    identityProviderWellKnownUrl = this.wellKnownUrl("mockaad").toString(),
                    acceptedAudience = listOf("correct_aud"),
                    softwareStatementJwks = signingKeySet
                )
            )
            val token = this.issueValidToken("client1")

            @Language("JSON")
            val invalidSoftwareStatement: String =
                """
                {
                  "appId": "cluster:ns:app1",
                  "accessPolicyInbound": [
                    "cluster:ns:app2"
                  ],
                  "accessPolicyOutbound": null
                }
                """.trimIndent()

            testApplication {
                application { tokenExchangeApp(config, DefaultRouting(config)) }
                client.post("registration/client") {
                    header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                    header(HttpHeaders.Authorization, "Bearer $token")
                    setBody(invalidSoftwareStatement)
                }.status shouldBe HttpStatusCode.BadRequest
                config.clientRegistry.findClient("cluster1:ns1:client1") shouldBe null
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
                    identityProviderWellKnownUrl = this.wellKnownUrl("mockaad").toString(),
                    acceptedAudience = listOf("correct_aud"),
                    softwareStatementJwks = signingKeySet
                )
            )
            val token = this.issueValidToken("client1")

            val invalidSoftwareStatement: String = ClientRegistrationRequest(
                "cluster1:ns1:client1",
                JsonWebKeys(jwkSet()),
                softwareStatementJwt(
                    SoftwareStatement(
                        appId = "cluster1:ns1:client1",
                        accessPolicyInbound = listOf("cluster1:ns1:client2"),
                        accessPolicyOutbound = emptyList()
                    ),
                    jwkSet().keys.first() as RSAKey
                )
            ).toJson()

            testApplication {
                application { tokenExchangeApp(config, DefaultRouting(config)) }
                client.post("registration/client") {
                    header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                    header(HttpHeaders.Authorization, "Bearer $token")
                    setBody(invalidSoftwareStatement)
                } shouldBeObject OAuth2Error.INVALID_REQUEST
                    .setDescription("token verification failed: Signed+JWT+rejected%3A+Another+algorithm+expected%2C+or+no+matching+key%28s%29+found")
                config.clientRegistry.findClient("cluster1:ns1:client1") shouldBe null
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
                    identityProviderWellKnownUrl = this.wellKnownUrl("mockaad").toString(),
                    acceptedAudience = listOf("correct_aud"),
                    softwareStatementJwks = signingKeySet
                )
            )
            val token = this.issueValidToken("client1")
            val invalidSoftwareStatement: String = ClientRegistrationRequest(
                "cluster1:ns1:client1",
                JsonWebKeys(JWKSet(emptyList())),
                softwareStatementJwt(
                    SoftwareStatement(
                        appId = "cluster1:ns1:client1",
                        accessPolicyInbound = listOf("cluster1:ns1:client2"),
                        accessPolicyOutbound = emptyList()
                    ),
                    signingKeySet.keys.first() as RSAKey
                )
            ).toJson()

            testApplication {
                application { tokenExchangeApp(config, DefaultRouting(config)) }
                client.post("registration/client") {
                    header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                    header(HttpHeaders.Authorization, "Bearer $token")
                    setBody(invalidSoftwareStatement)
                } shouldBeObject OAuth2Error.INVALID_REQUEST.setDescription("empty JWKS not allowed")
                config.clientRegistry.findClient("cluster1:ns1:client1") shouldBe null
            }
        }
    }

    @Test
    fun `delete non-existent client should return 204 No Content`() {
        withMockOAuth2Server {
            val config = mockConfig(
                this,
                ClientRegistrationAuthProperties(
                    identityProviderWellKnownUrl = this.wellKnownUrl("mockaad").toString(),
                    acceptedAudience = listOf("correct_aud"),
                    softwareStatementJwks = jwkSet()
                )
            )
            val token = this.issueValidToken("client1")
            testApplication {
                application { tokenExchangeApp(config, DefaultRouting(config)) }
                client.delete("registration/client/yolo") {
                    header(HttpHeaders.Authorization, "Bearer $token")
                }.status shouldBe HttpStatusCode.NoContent
                config.clientRegistry.findClient("yolo") shouldBe null
            }
        }
    }

    @Test
    fun `delete existing client should return 204 No Content`() {
        withMockOAuth2Server {
            val config = mockConfig(
                this,
                ClientRegistrationAuthProperties(
                    identityProviderWellKnownUrl = this.wellKnownUrl("mockaad").toString(),
                    acceptedAudience = listOf("correct_aud"),
                    softwareStatementJwks = jwkSet()
                )
            )
            val client1 = config.clientRegistry.let { it as MockClientRegistry }.register("client1")
            config.clientRegistry.findClient(client1.clientId) shouldBe client1
            val token = this.issueValidToken("client1")
            testApplication {
                application { tokenExchangeApp(config, DefaultRouting(config)) }
                client.delete("registration/client/${client1.clientId}") {
                    header(HttpHeaders.Authorization, "Bearer $token")
                }.status shouldBe HttpStatusCode.NoContent
                config.clientRegistry.findClient(client1.clientId) shouldBe null
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

    private fun MockOAuth2Server.issueValidToken(clientId: String): String =
        this.issueToken(
            "mockaad",
            clientId,
            DefaultOAuth2TokenCallback(
                issuerId = "mockaad",
                subject = clientId,
                audience = listOf("correct_aud"),
                claims = mapOf("roles" to BearerTokenAuth.ACCEPTED_ROLES_CLAIM_VALUE)
            )
        ).serialize()
}
