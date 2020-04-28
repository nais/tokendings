package io.nais.security.oauth2.mock

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import io.ktor.client.request.forms.submitForm
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.http.ContentType
import io.ktor.http.contentType
import io.ktor.http.parametersOf
import io.nais.security.oauth2.Jackson
import io.nais.security.oauth2.defaultHttpClient
import io.nais.security.oauth2.model.ClientId
import io.nais.security.oauth2.model.ClientRegistration
import io.nais.security.oauth2.model.ClientRegistrationRequest
import io.nais.security.oauth2.model.JsonWebKeys
import io.nais.security.oauth2.model.OAuth2TokenResponse
import io.nais.security.oauth2.model.SoftwareStatement
import io.nais.security.oauth2.model.SoftwareStatementJwt
import io.nais.security.oauth2.token.JwtTokenProvider.Companion.generateJWKSet
import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import java.time.Instant
import java.util.Date
import java.util.UUID

internal class MockAdminClient(
    val serverPort: Int,
    val clientId: ClientId,
    val clientRegistrationEndpoint: String,
    val tokenEndpoint: String
) {
    private var jwkSet = generateJWKSet("jwker-initial-key", 2048)
    val mockWebServer = MockWebServer()

    fun start() =
        mockWebServer.apply {
            start(serverPort)
            dispatcher = object : Dispatcher() {
                override fun dispatch(request: RecordedRequest): MockResponse {
                    try {
                        return when (request.path) {

                            "/jwks" -> MockResponse()
                                .setHeader("ContentType", ContentType.Application.Json.toString())
                                .setBody(Jackson.defaultMapper.writeValueAsString(JsonWebKeys(jwkSet.toPublicJWKSet())))

                            "/rotate" -> {
                                val clientRegistration: ClientRegistration = rotateKeys()
                                MockResponse()
                                    .setHeader("ContentType", ContentType.Application.Json.toString())
                                    .setBody(Jackson.defaultMapper.writeValueAsString(clientRegistration))
                            }

                            else -> MockResponse().setResponseCode(404)
                        }
                    } catch (e: Exception) {
                        return MockResponse().setResponseCode(500)
                    }
                }
            }
        }

    fun jwksUrl(): String = mockWebServer.url("/jwks").toString()

    fun shutdown() = mockWebServer.shutdown()

    fun rotateKeys(): ClientRegistration {
        val rsaKey = jwkSet.keys.first() as RSAKey
        val newJwkSet = generateJWKSet("jwker-rotated-key", 2048)
        val clientRegistration: ClientRegistration = registerNewJWKSet(newJwkSet, rsaKey)
        jwkSet = newJwkSet
        return clientRegistration
    }

    private fun registerNewJWKSet(newJwkSet: JWKSet, rsaKey: RSAKey): ClientRegistration = runBlocking {
        val tokenResponse: OAuth2TokenResponse = requestBearerToken(rsaKey)
        defaultHttpClient.post<ClientRegistration>(clientRegistrationEndpoint) {
            header("Authorization", "Bearer ${tokenResponse.accessToken}")
            contentType(ContentType.Application.Json)
            body = ClientRegistrationRequest(
                clientName = clientId,
                jwks = JsonWebKeys(newJwkSet),
                softwareStatement = SoftwareStatement(clientId).sign(rsaKey),
                scopes = listOf(clientRegistrationEndpoint),
                grantTypes = listOf("client_credentials")
            )
        }
    }

    private fun SoftwareStatement.sign(rsaKey: RSAKey): SoftwareStatementJwt =
        SignedJWT(
            JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(rsaKey.keyID)
                .type(JOSEObjectType.JWT).build(),
            JWTClaimsSet.parse(Jackson.defaultMapper.writeValueAsString(this))
        ).apply {
            sign(RSASSASigner(rsaKey.toPrivateKey()))
        }.serialize()

    private fun requestBearerToken(rsaKey: RSAKey): OAuth2TokenResponse = runBlocking {
        val clientAssertion = createClientAssertion(rsaKey)
        defaultHttpClient.submitForm<OAuth2TokenResponse>(
            url = tokenEndpoint,
            formParameters = parametersOf(
                "client_assertion_type" to listOf("urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
                "client_assertion" to listOf(clientAssertion),
                "grant_type" to listOf("client_credentials"),
                "scope" to listOf(clientRegistrationEndpoint)
            ),
            encodeInQuery = false
        )
    }

    // TODO fix audience in this token
    private fun createClientAssertion(rsaKey: RSAKey): String =
        SignedJWT(
            JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(rsaKey.keyID)
                .type(JOSEObjectType.JWT).build(),
            JWTClaimsSet.Builder()
                .issuer(clientId)
                .subject(clientId)
                .audience(tokenEndpoint)
                .issueTime(Date.from(Instant.now()))
                .expirationTime(Date.from(Instant.now().plusSeconds(3600)))
                .jwtID(UUID.randomUUID().toString())
                .build()
        ).apply {
            sign(RSASSASigner(rsaKey.toPrivateKey()))
        }.serialize().also {
            println("client_assertion: $it")
        }
}
