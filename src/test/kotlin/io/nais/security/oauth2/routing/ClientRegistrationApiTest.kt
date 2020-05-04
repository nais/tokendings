package io.nais.security.oauth2.routing

import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jwt.JWTClaimsSet
import io.kotlintest.shouldBe
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.server.testing.handleRequest
import io.ktor.server.testing.setBody
import io.ktor.server.testing.withTestApplication
import io.nais.security.oauth2.config.ClientReqistrationAuthProperties
import io.nais.security.oauth2.mock.MockApp
import io.nais.security.oauth2.mock.mockConfig
import io.nais.security.oauth2.mock.withMockOAuth2Server
import io.nais.security.oauth2.model.ClientRegistrationRequest
import io.nais.security.oauth2.model.JsonWebKeys
import io.nais.security.oauth2.model.SoftwareStatement
import io.nais.security.oauth2.model.SoftwareStatementJwt
import io.nais.security.oauth2.token.sign
import io.nais.security.oauth2.utils.jwkSet
import no.nav.security.mock.oauth2.token.DefaultOAuth2TokenCallback
import org.junit.jupiter.api.Test

internal class ClientRegistrationApiTest {

    @Test
    fun `401 on unauthorized requests`() {
        withMockOAuth2Server {
            val mockConfig = mockConfig(
                this, ClientReqistrationAuthProperties(
                    this.wellKnownUrl("mockaad").toString(),
                    emptyList()
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
                ClientReqistrationAuthProperties(
                    this.wellKnownUrl("mockaad").toString(),
                    listOf("correct_aud")
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
            val config = mockConfig(
                this,
                ClientReqistrationAuthProperties(
                    this.wellKnownUrl("mockaad").toString(),
                    listOf("correct_aud")
                )
            )
            val token = this.issueToken(
                "mockaad", "client1", DefaultOAuth2TokenCallback(
                    issuerId = "mockaad",
                    subject = "client1",
                    audience = "correct_aud"
                )
            ).serialize()

            val signingKeySet = jwkSet()

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

    private fun softwareStatementJwt(softwareStatement: SoftwareStatement, rsaKey: RSAKey): SoftwareStatementJwt =
        JWTClaimsSet.Builder()
            .claim("appId", softwareStatement.appId)
            .claim("accessPolicyInbound", softwareStatement.accessPolicyInbound)
            .claim("accessPolicyOutbound", softwareStatement.accessPolicyOutbound)
            .build()
            .sign(rsaKey)
            .serialize()
}
