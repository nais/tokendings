package io.nais.security.oauth2.routing

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.proc.JWSVerificationKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.http.formUrlEncode
import io.ktor.server.testing.handleRequest
import io.ktor.server.testing.setBody
import io.ktor.server.testing.withTestApplication
import io.nais.security.oauth2.config.AuthorizationServerProperties.Companion.jwksPath
import io.nais.security.oauth2.config.AuthorizationServerProperties.Companion.wellKnownPath
import io.nais.security.oauth2.mock.MockClientRegistry
import io.nais.security.oauth2.mock.generateClientAssertion
import io.nais.security.oauth2.mock.mockConfig
import io.nais.security.oauth2.mock.withMockOAuth2Server
import io.nais.security.oauth2.model.AccessPolicy
import io.nais.security.oauth2.model.OAuth2TokenResponse
import io.nais.security.oauth2.model.WellKnown
import io.nais.security.oauth2.token.JwtTokenProvider.Companion.generateJWKSet
import io.nais.security.oauth2.tokenExchangeApp
import no.nav.security.mock.oauth2.token.DefaultOAuth2TokenCallback
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

internal class TokenExchangeApiTest {
    val mapper = jacksonObjectMapper()

    @Test
    fun `call to well-known should return server metadata`() {
        withMockOAuth2Server {
            val mockConfig = mockConfig(this)
            withTestApplication({
                tokenExchangeApp(mockConfig, DefaultRouting(mockConfig))
            }) {
                with(handleRequest(HttpMethod.Get, wellKnownPath)) {
                    assertThat(response.status()).isEqualTo(HttpStatusCode.OK)
                    val wellKnown: WellKnown = mapper.readValue(response.content!!)
                    assertThat(wellKnown.issuer).isEqualTo(mockConfig.authorizationServerProperties.issuerUrl)
                }
            }
        }
    }

    @Test
    fun `call to jwks should return public keyset only`() {
        withMockOAuth2Server {
            val mockConfig = mockConfig(this)
            withTestApplication({
                tokenExchangeApp(mockConfig, DefaultRouting(mockConfig))
            }) {
                with(handleRequest(HttpMethod.Get, jwksPath)) {
                    assertThat(response.status()).isEqualTo(HttpStatusCode.OK)
                    val jwkSet: JWKSet = JWKSet.parse(response.content!!)
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
            val registry = (mockConfig.clientRegistry as MockClientRegistry)
            val client1 = registry.registerClientAndGenerateKeys("client1", AccessPolicy())
            val client2 = registry.registerClientAndGenerateKeys(
                "client2",
                AccessPolicy(listOf("client1"))
            )
            val clientAssertion = registry.generateClientAssertionFor(client1.clientId).serialize()
            val subjectToken = this.issueToken("mock1", "someclientid", DefaultOAuth2TokenCallback())

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
                            "subject_token" to subjectToken.serialize()
                        ).formUrlEncode()
                    )
                }) {
                    assertThat(response.status()).isEqualTo(HttpStatusCode.OK)
                    val accessTokenResponse: OAuth2TokenResponse = mapper.readValue(response.content!!)
                    assertThat(accessTokenResponse.accessToken).isNotBlank()
                    val signedJWT = SignedJWT.parse(accessTokenResponse.accessToken)
                    val claims = signedJWT.verifySignature(mockConfig.tokenIssuer.publicJwkSet())
                    assertThat(claims.subject).isEqualTo(subjectToken.jwtClaimsSet.subject)
                    assertThat(claims.issuer).isEqualTo(mockConfig.authorizationServerProperties.issuerUrl)
                    assertThat(claims.audience).containsExactly(client2.clientId)
                }
            }
        }
    }

    @Test
    fun `token exchange call with valid client and subject_token, but incorrect access policy should fail`() {
        withMockOAuth2Server {
            val mockConfig = mockConfig(this)
            val registry = (mockConfig.clientRegistry as MockClientRegistry)
            val client1 = registry.registerClientAndGenerateKeys("client1", AccessPolicy())
            val client2 = registry.registerClientAndGenerateKeys("client2", AccessPolicy())
            val clientAssertion = registry.generateClientAssertionFor(client1.clientId).serialize()
            val subjectToken = this.issueToken("mock1", "someclientid", DefaultOAuth2TokenCallback())

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
                            "subject_token" to subjectToken.serialize()
                        ).formUrlEncode()
                    )
                }) {
                    assertThat(response.status()).isEqualTo(HttpStatusCode.BadRequest)
                    val errorResponse: ErrorResponse = mapper.readValue(response.content!!)
                    assertThat(errorResponse.code).isEqualTo("invalid_request")
                }
            }
        }
    }

    @Test
    fun `token exchange call with invalid client assertion should fail`() {
        withMockOAuth2Server {
            val mockConfig = mockConfig(this)
            val jwkSet = generateJWKSet("akey", 2048)
            val unknownClientAssertion = generateClientAssertion(
                "unknown",
                mockConfig.authorizationServerProperties.tokenEndpointUrl(),
                jwkSet
            )
            withTestApplication({
                tokenExchangeApp(mockConfig, DefaultRouting(mockConfig))
            }) {
                with(handleRequest(HttpMethod.Post, "/token") {
                    addHeader(HttpHeaders.ContentType, ContentType.Application.FormUrlEncoded.toString())
                    setBody(
                        listOf(
                            "client_assertion_type" to "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                            "client_assertion" to unknownClientAssertion.serialize(),
                            "grant_type" to "urn:ietf:params:oauth:grant-type:token-exchange",
                            "audience" to "client2",
                            "subject_token_type" to "urn:ietf:params:oauth:token-type:jwt",
                            "subject_token" to "sometoken"
                        ).formUrlEncode()
                    )
                }) {
                    assertThat(response.status()).isEqualTo(HttpStatusCode.Unauthorized)
                    val errorResponse: ErrorResponse = mapper.readValue(response.content!!)
                    assertThat(errorResponse.code).isEqualTo("invalid_client")
                }
            }
        }
    }
}

@JsonInclude(JsonInclude.Include.NON_NULL)
data class ErrorResponse(
    val code: String,
    val description: String,
    val uri: String?,
    val httpstatusCode: Int
)

private fun SignedJWT.verifySignature(jwks: JWKSet): JWTClaimsSet =
    DefaultJWTProcessor<SecurityContext?>().apply {
        jwsKeySelector = JWSVerificationKeySelector(JWSAlgorithm.RS256, ImmutableJWKSet(jwks))
    }.process(this, null)
