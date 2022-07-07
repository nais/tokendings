package io.nais.security.oauth2.routing

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.PlainJWT
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.oauth2.sdk.OAuth2Error
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType.Application.FormUrlEncoded
import io.ktor.http.HttpHeaders.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.formUrlEncode
import io.ktor.server.testing.testApplication
import io.nais.security.oauth2.config.AppConfiguration
import io.nais.security.oauth2.config.AuthorizationServerProperties.Companion.jwksPath
import io.nais.security.oauth2.config.AuthorizationServerProperties.Companion.wellKnownPath
import io.nais.security.oauth2.mock.MockClientRegistry
import io.nais.security.oauth2.mock.mockConfig
import io.nais.security.oauth2.mock.withMockOAuth2Server
import io.nais.security.oauth2.model.AccessPolicy
import io.nais.security.oauth2.model.ClientId
import io.nais.security.oauth2.model.JsonWebKeys
import io.nais.security.oauth2.model.OAuth2Client
import io.nais.security.oauth2.model.OAuth2TokenResponse
import io.nais.security.oauth2.model.WellKnown
import io.nais.security.oauth2.token.sign
import io.nais.security.oauth2.tokenExchangeApp
import io.nais.security.oauth2.utils.jwkSet
import io.nais.security.oauth2.utils.shouldBeObject
import io.nais.security.oauth2.utils.verifySignature
import io.prometheus.client.CollectorRegistry
import no.nav.security.mock.oauth2.token.DefaultOAuth2TokenCallback
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Test
import java.net.URLEncoder
import java.time.Instant
import java.util.Date
import java.util.UUID

internal class TokenExchangeApiTest {
    private val mapper = jacksonObjectMapper()

    @AfterEach
    fun tearDown() {
        CollectorRegistry.defaultRegistry.clear()
    }

    @Test
    fun `call to well-known should successfully return server metadata`() {
        withMockOAuth2Server {
            val mockConfig = mockConfig(this)
            testApplication {
                application { tokenExchangeApp(mockConfig, DefaultRouting(mockConfig)) }
                with(client.get(wellKnownPath)) {
                    assertThat(status).isEqualTo(HttpStatusCode.OK)
                    val wellKnown: WellKnown = mapper.readValue(bodyAsText())
                    assertThat(wellKnown.issuer).isEqualTo(mockConfig.authorizationServerProperties.issuerUrl)
                }
            }
        }
    }

    @Test
    fun `call to jwks should only return public keyset`() {
        withMockOAuth2Server {
            val mockConfig = mockConfig(this)
            testApplication {
                application { tokenExchangeApp(mockConfig, DefaultRouting(mockConfig)) }
                with(client.get(jwksPath)) {
                    assertThat(status).isEqualTo(HttpStatusCode.OK)
                    val jwkSet: JWKSet = JWKSet.parse(bodyAsText())
                    assertThat(jwkSet.keys).isNotEmpty
                    jwkSet.keys.forEach {
                        assertThat(it.isPrivate).isEqualTo(false)
                    }
                }
            }
        }
    }

    @Test
    fun `successful token exchange call with valid client and subject_token`() {
        withMockOAuth2Server {
            val mockConfig = mockConfig(this)

            val client1 = mockConfig.mockClientRegistry().register("client1")
            val client2 = mockConfig.mockClientRegistry().register("client2", AccessPolicy(listOf("client1")))
            val clientAssertion = client1.createClientAssertion(mockConfig.authorizationServerProperties.tokenEndpointUrl())
            val subjectToken = this.issueToken("mock1", "someclientid", DefaultOAuth2TokenCallback())

            testApplication {
                application { tokenExchangeApp(mockConfig, DefaultRouting(mockConfig)) }
                val response = client.post("/token") {
                    header(ContentType, FormUrlEncoded.toString())
                    setBody(
                        listOf(
                            "client_assertion_type" to "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                            "client_assertion" to clientAssertion,
                            "grant_type" to "urn:ietf:params:oauth:grant-type:token-exchange",
                            "audience" to client2.clientId,
                            "subject_token_type" to "urn:ietf:params:oauth:token-type:jwt",
                            "subject_token" to subjectToken.serialize()
                        ).formUrlEncode()
                    )
                }
                assertThat(response.status).isEqualTo(HttpStatusCode.OK)
                val accessTokenResponse: OAuth2TokenResponse = mapper.readValue(response.bodyAsText())
                assertThat(accessTokenResponse.accessToken).isNotBlank
                val signedJWT = SignedJWT.parse(accessTokenResponse.accessToken)
                val claims = signedJWT.verifySignature(mockConfig.tokenIssuer.publicJwkSet())
                assertThat(claims.subject).isEqualTo(subjectToken.jwtClaimsSet.subject)
                assertThat(claims.issuer).isEqualTo(mockConfig.authorizationServerProperties.issuerUrl)
                assertThat(claims.audience).containsExactly(client2.clientId)
            }
        }
    }

    @Test
    fun `token exchange call with valid client and subject_token, but incorrect access policy should fail`() {
        withMockOAuth2Server {
            val mockConfig = mockConfig(this)
            val client1 = mockConfig.mockClientRegistry().register("client1")
            val client2 = mockConfig.mockClientRegistry().register("client2", AccessPolicy(listOf("client3")))
            val clientAssertion = client1.createClientAssertion(mockConfig.authorizationServerProperties.tokenEndpointUrl())
            val subjectToken = this.issueToken("mock1", "someclientid", DefaultOAuth2TokenCallback())

            testApplication {
                application { tokenExchangeApp(mockConfig, DefaultRouting(mockConfig)) }
                client.post("/token") {
                    header(ContentType, FormUrlEncoded.toString())
                    setBody(
                        listOf(
                            "client_assertion_type" to "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                            "client_assertion" to clientAssertion,
                            "grant_type" to "urn:ietf:params:oauth:grant-type:token-exchange",
                            "audience" to client2.clientId,
                            "subject_token_type" to "urn:ietf:params:oauth:token-type:jwt",
                            "subject_token" to subjectToken.serialize()
                        ).formUrlEncode()
                    )
                } shouldBeObject OAuth2Error.INVALID_REQUEST
                    .setDescription("client '${client1.clientId}' is not authorized to get token with aud=${client2.clientId}")
            }
        }
    }

    @Test
    fun `token exchange call with unknown client should fail`() {
        withMockOAuth2Server {
            val mockConfig = mockConfig(this)
            val unknownClientAssertion = oAuth2Client().createClientAssertion(mockConfig.authorizationServerProperties.tokenEndpointUrl())

            testApplication {
                application { tokenExchangeApp(mockConfig, DefaultRouting(mockConfig)) }
                client.post("/token") {
                    header(ContentType, FormUrlEncoded.toString())
                    setBody(
                        listOf(
                            "client_assertion_type" to "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                            "client_assertion" to unknownClientAssertion,
                            "grant_type" to "urn:ietf:params:oauth:grant-type:token-exchange",
                            "audience" to "client2",
                            "subject_token_type" to "urn:ietf:params:oauth:token-type:jwt",
                            "subject_token" to "sometoken"
                        ).formUrlEncode()
                    )
                } shouldBeObject OAuth2Error.INVALID_CLIENT.setDescription("invalid client authentication for client_id=unknown, client not registered.")
            }
        }
    }

    @Test
    fun `token exchange call with invalid client assertion keys should fail`() {
        withMockOAuth2Server {
            val mockConfig = mockConfig(this)
            val client1 = mockConfig.mockClientRegistry().register("client1")
            val invalidClientAssertion = client1.createClientAssertionInvalidKeys(mockConfig.authorizationServerProperties.tokenEndpointUrl())

            testApplication {
                application { tokenExchangeApp(mockConfig, DefaultRouting(mockConfig)) }
                client.post("/token") {
                    header(ContentType, FormUrlEncoded.toString())
                    setBody(
                        listOf(
                            "client_assertion_type" to "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                            "client_assertion" to invalidClientAssertion,
                            "grant_type" to "urn:ietf:params:oauth:grant-type:token-exchange",
                            "audience" to "client2",
                            "subject_token_type" to "urn:ietf:params:oauth:token-type:jwt",
                            "subject_token" to "sometoken"
                        ).formUrlEncode()
                    )
                } shouldBeObject OAuth2Error.INVALID_REQUEST
                    .setDescription("token verification failed: Signed+JWT+rejected%3A+Another+algorithm+expected%2C+or+no+matching+key%28s%29+found")
            }
        }
    }

    @Test
    fun `token exchange call with invalid audience should fail`() {
        withMockOAuth2Server {
            val mockConfig = mockConfig(this)
            val client1 = mockConfig.mockClientRegistry().register("client1")

            val invalidAudience = "yolo"
            val invalidClientAssertion = client1.createClientAssertion(audience = invalidAudience)
            val expectedAudience = URLEncoder.encode(mockConfig.authorizationServerProperties.tokenEndpointUrl(), Charsets.UTF_8)

            testApplication {
                application { tokenExchangeApp(mockConfig, DefaultRouting(mockConfig)) }
                client.post("/token") {
                    header(ContentType, FormUrlEncoded.toString())
                    setBody(
                        listOf(
                            "client_assertion_type" to "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                            "client_assertion" to invalidClientAssertion,
                            "grant_type" to "urn:ietf:params:oauth:grant-type:token-exchange",
                            "audience" to "client2",
                            "subject_token_type" to "urn:ietf:params:oauth:token-type:jwt",
                            "subject_token" to "sometoken"
                        ).formUrlEncode()
                    )
                } shouldBeObject OAuth2Error.INVALID_REQUEST
                    .setDescription("token verification failed: JWT+aud+claim+has+value+%5B$invalidAudience%5D%2C+must+be+%5B$expectedAudience%5D")
            }
        }
    }

    @Test
    fun `token exchange call with client assertion lifetime exceeding max lifetime should fail`() {
        withMockOAuth2Server {
            val mockConfig = mockConfig(this)

            val client1 = mockConfig.mockClientRegistry().register("client1")
            val client2 = mockConfig.mockClientRegistry().register("client2", AccessPolicy(listOf(client1.clientId)))
            val clientAssertion = client1.createClientAssertion(audience = mockConfig.authorizationServerProperties.tokenEndpointUrl(), lifetime = 3600)
            val subjectToken = this.issueToken("mock1", "someclientid", DefaultOAuth2TokenCallback())

            testApplication {
                application { tokenExchangeApp(mockConfig, DefaultRouting(mockConfig)) }
                client.post("/token") {
                    header(ContentType, FormUrlEncoded.toString())
                    setBody(
                        listOf(
                            "client_assertion_type" to "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                            "client_assertion" to clientAssertion,
                            "grant_type" to "urn:ietf:params:oauth:grant-type:token-exchange",
                            "audience" to client2.clientId,
                            "subject_token_type" to "urn:ietf:params:oauth:token-type:jwt",
                            "subject_token" to subjectToken.serialize()
                        ).formUrlEncode()
                    )
                } shouldBeObject OAuth2Error.INVALID_CLIENT
                    .setDescription(
                        "invalid client authentication for client_id=${client1.clientId}, client assertion exceeded " +
                            "max lifetime (${mockConfig.authorizationServerProperties.clientAssertionMaxExpiry}s)."
                    )
            }
        }
    }

    @Test
    fun `token exchange call with client assertion issued in the future should fail`() {
        withMockOAuth2Server {
            val mockConfig = mockConfig(this)

            val client1 = mockConfig.mockClientRegistry().register("client1")
            val client2 = mockConfig.mockClientRegistry().register("client2", AccessPolicy(listOf(client1.clientId)))
            val clientAssertion = client1.createClientAssertion(
                audience = mockConfig.authorizationServerProperties.tokenEndpointUrl(),
                issueTime = Date.from(Instant.now().plusSeconds(62))
            )
            val subjectToken = this.issueToken("mock1", "someclientid", DefaultOAuth2TokenCallback())

            testApplication {
                application { tokenExchangeApp(mockConfig, DefaultRouting(mockConfig)) }
                client.post("/token") {
                    header(ContentType, FormUrlEncoded.toString())
                    setBody(
                        listOf(
                            "client_assertion_type" to "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                            "client_assertion" to clientAssertion,
                            "grant_type" to "urn:ietf:params:oauth:grant-type:token-exchange",
                            "audience" to client2.clientId,
                            "subject_token_type" to "urn:ietf:params:oauth:token-type:jwt",
                            "subject_token" to subjectToken.serialize()
                        ).formUrlEncode()
                    )
                } shouldBeObject OAuth2Error.INVALID_REQUEST.setDescription("token verification failed: JWT+before+use+time")
            }
        }
    }

    @Test
    fun `token exchange call with unsigned client assertion should fail`() {
        withMockOAuth2Server {
            val mockConfig = mockConfig(this)

            val client1 = mockConfig.mockClientRegistry().register("client1")
            val client2 = mockConfig.mockClientRegistry().register("client2", AccessPolicy(listOf(client1.clientId)))
            val clientAssertion = PlainJWT(
                JWTClaimsSet.Builder()
                    .issuer(this.issuerUrl("mock1").toString())
                    .subject("oloy")
                    .audience("yolo")
                    .issueTime(Date.from(Instant.now()))
                    .expirationTime(Date.from(Instant.now().plusSeconds(3600)))
                    .jwtID(UUID.randomUUID().toString())
                    .build()
            ).serialize()
            val subjectToken = this.issueToken("mock1", "someclientid", DefaultOAuth2TokenCallback())

            testApplication {
                application { tokenExchangeApp(mockConfig, DefaultRouting(mockConfig)) }
                client.post("/token") {
                    header(ContentType, FormUrlEncoded.toString())
                    setBody(
                        listOf(
                            "client_assertion_type" to "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                            "client_assertion" to clientAssertion,
                            "grant_type" to "urn:ietf:params:oauth:grant-type:token-exchange",
                            "audience" to client2.clientId,
                            "subject_token_type" to "urn:ietf:params:oauth:token-type:jwt",
                            "subject_token" to subjectToken.serialize()
                        ).formUrlEncode()
                    )
                } shouldBeObject OAuth2Error.INVALID_REQUEST.setDescription("invalid request, cannot parse token")
            }
        }
    }

    @Test
    fun `token exchange call with unknown issuer in subject token should fail`() {
        withMockOAuth2Server {
            val mockConfig = mockConfig(this)
            val client1 = mockConfig.mockClientRegistry().register("client1")
            val client2 = mockConfig.mockClientRegistry().register("client2", AccessPolicy(listOf(client1.clientId)))
            val clientAssertion = client1.createClientAssertion(mockConfig.authorizationServerProperties.tokenEndpointUrl())
            val subjectToken = this.issueToken("unknown", "someclient", DefaultOAuth2TokenCallback())
            val subjectTokenSerialized = subjectToken.serialize()

            testApplication {
                application { tokenExchangeApp(mockConfig, DefaultRouting(mockConfig)) }
                client.post("/token") {
                    header(ContentType, FormUrlEncoded.toString())
                    setBody(
                        listOf(
                            "client_assertion_type" to "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                            "client_assertion" to clientAssertion,
                            "grant_type" to "urn:ietf:params:oauth:grant-type:token-exchange",
                            "audience" to client2.clientId,
                            "subject_token_type" to "urn:ietf:params:oauth:token-type:jwt",
                            "subject_token" to subjectTokenSerialized
                        ).formUrlEncode()
                    )
                } shouldBeObject OAuth2Error.INVALID_REQUEST
                    .setDescription("invalid subject_token: invalid request, cannot validate token from issuer=${subjectToken.jwtClaimsSet.issuer}")
            }
        }
    }

    @Test
    fun `token exchange call with unsigned subject token should fail`() {
        withMockOAuth2Server {
            val mockConfig = mockConfig(this)
            val client1 = mockConfig.mockClientRegistry().register("client1")
            val client2 = mockConfig.mockClientRegistry().register("client2", AccessPolicy(listOf(client1.clientId)))
            val clientAssertion = client1.createClientAssertion(mockConfig.authorizationServerProperties.tokenEndpointUrl())
            val subjectToken = PlainJWT(
                JWTClaimsSet.Builder()
                    .issuer(this.issuerUrl("mock1").toString())
                    .subject("oloy")
                    .audience("yolo")
                    .issueTime(Date.from(Instant.now()))
                    .expirationTime(Date.from(Instant.now().plusSeconds(3600)))
                    .jwtID(UUID.randomUUID().toString())
                    .build()
            ).serialize()

            testApplication {
                application { tokenExchangeApp(mockConfig, DefaultRouting(mockConfig)) }
                client.post("/token") {
                    header(ContentType, FormUrlEncoded.toString())
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
                } shouldBeObject OAuth2Error.INVALID_REQUEST.setDescription("invalid subject_token: invalid request, cannot parse token")
            }
        }
    }

    @Test
    fun `token exchange with valid client and expired subject_token should fail`() {
        withMockOAuth2Server {
            val mockConfig = mockConfig(this)

            val client1 = mockConfig.mockClientRegistry().register("client1")
            val client2 = mockConfig.mockClientRegistry().register("client2", AccessPolicy(listOf("client1")))
            val clientAssertion = client1.createClientAssertion(mockConfig.authorizationServerProperties.tokenEndpointUrl())
            val expiryInSeconds = -60L
            val subjectToken = this.issueToken("mock1", "someclientid", DefaultOAuth2TokenCallback(expiry = expiryInSeconds))

            testApplication {
                application { tokenExchangeApp(mockConfig, DefaultRouting(mockConfig)) }
                client.post("/token") {
                    header(ContentType, FormUrlEncoded.toString())
                    setBody(
                        listOf(
                            "client_assertion_type" to "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                            "client_assertion" to clientAssertion,
                            "grant_type" to "urn:ietf:params:oauth:grant-type:token-exchange",
                            "audience" to client2.clientId,
                            "subject_token_type" to "urn:ietf:params:oauth:token-type:jwt",
                            "subject_token" to subjectToken.serialize()
                        ).formUrlEncode()
                    )
                } shouldBeObject OAuth2Error.INVALID_REQUEST.setDescription("invalid subject_token: token verification failed: Expired+JWT")
            }
        }
    }

    private fun AppConfiguration.mockClientRegistry() = this.clientRegistry as MockClientRegistry

    private fun oAuth2Client(clientId: ClientId = "unknown") = OAuth2Client(clientId, JsonWebKeys(jwkSet()))

    private fun OAuth2Client.createClientAssertionInvalidKeys(audience: String) =
        createClientAssertion(audience = audience, jwkSet = jwkSet())

    private fun OAuth2Client.createClientAssertion(
        audience: String,
        lifetime: Long = 119,
        jwkSet: JWKSet = this.jwkSet,
        issueTime: Date = Date.from(Instant.now())
    ) =
        JWTClaimsSet.Builder()
            .issuer(clientId)
            .subject(clientId)
            .audience(audience)
            .issueTime(issueTime)
            .expirationTime(Date.from(Instant.now().plusSeconds(lifetime)))
            .notBeforeTime(issueTime)
            .jwtID(UUID.randomUUID().toString())
            .build()
            .sign(jwkSet.keys.first() as RSAKey)
            .serialize()
}
