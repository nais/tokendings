package io.nais.security.oauth2.mock

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.engine.cio.CIO
import io.ktor.client.plugins.ClientRequestException
import io.ktor.client.request.delete
import io.ktor.client.request.forms.submitForm
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.client.utils.EmptyContent
import io.ktor.http.ContentType.Application.Json
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.http.parametersOf
import io.ktor.serialization.jackson.jackson
import io.ktor.server.application.Application
import io.ktor.server.application.call
import io.ktor.server.application.install
import io.ktor.server.engine.applicationEngineEnvironment
import io.ktor.server.engine.connector
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.plugins.statuspages.StatusPages
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.routing.delete
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.route
import io.ktor.server.routing.routing
import io.nais.security.oauth2.model.ClientRegistration
import io.nais.security.oauth2.model.ClientRegistrationRequest
import io.nais.security.oauth2.model.JsonWebKeys
import io.nais.security.oauth2.model.OAuth2Client
import io.nais.security.oauth2.model.OAuth2TokenResponse
import io.nais.security.oauth2.model.SoftwareStatement
import kotlinx.coroutines.runBlocking
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.time.Instant
import java.util.Date
import java.util.UUID

data class ClientConfig(
    val jwkerClientId: String = "jwker_client_id_1",
    val bearerTokenScope: String = "tokendings",
    val identityProviderTokenEndpoint: String = "http://localhost:1111/aadmock/token",
    val registrationEndpoint: String = "http://localhost:8080/registration/client",
    val signingKey: RSAKey = "jwker-jwks.json".asResource().readText().let {
        JWKSet.parse(it).keys.first() as RSAKey
    }
)

fun main() {
    embeddedServer(
        Netty,
        applicationEngineEnvironment {
            connector {
                port = 8181
            }
            module {
                mockJwkerApp()
            }
        }
    ).start()
}

fun Application.mockJwkerApp() {
    val tokenDingsClient = TokenDingsClient()

    install(ContentNegotiation) {
        jackson { }
    }

    install(StatusPages) {
        exception<Throwable> { call, error ->
            log.debug("received exception:", error)
            when (error) {
                is ClientRequestException -> {
                    val statusCode: HttpStatusCode = error.response.status
                    val body: Any = if (statusCode != HttpStatusCode.NoContent) {
                        error.response.bodyAsText()
                    } else {
                        EmptyContent
                    }

                    call.respond(statusCode, body)
                }
                else -> {
                    call.respond(HttpStatusCode.InternalServerError, error.message ?: "unknown internal server error")
                }
            }
        }
    }

    routing {
        route("/jwker/apps") {
            get {
                call.respond(tokenDingsClient.getClients())
            }
            get("/{clientId}") {
                val clientId: String = requireNotNull(call.parameters["clientId"])
                tokenDingsClient.getClient(clientId)?.let {
                    call.respond(it)
                } ?: call.respond(HttpStatusCode.NotFound, "client not found")
            }
            delete("/{clientId}") {
                val clientId: String = requireNotNull(call.parameters["clientId"])
                tokenDingsClient.deleteClient(clientId)
                call.respond(HttpStatusCode.NoContent)
            }
            delete {
                tokenDingsClient.deleteWithoutId()
            }
            post {
                val softwareStatement: SoftwareStatement = call.receive()
                val clientRegistration: ClientRegistration = tokenDingsClient.registerClient(softwareStatement)
                call.respond(HttpStatusCode.Created, clientRegistration)
            }
        }
    }
}

class TokenDingsClient(private val config: ClientConfig = ClientConfig()) {

    suspend fun registerClient(
        softwareStatement: SoftwareStatement
    ): ClientRegistration =
        requestBearerToken().let {
            log.debug("using bearer token ${it.accessToken}")
            httpClient.post(config.registrationEndpoint) {
                header("Authorization", "Bearer ${it.accessToken}")
                contentType(Json)
                setBody(
                    ClientRegistrationRequest(
                        clientName = softwareStatement.appId,
                        jwks = JsonWebKeys(JWKSet(createJWK())),
                        softwareStatementJwt = softwareStatement.sign(),
                        scopes = listOf(),
                        grantTypes = listOf()
                    )
                )
            }.body()
        }

    suspend fun deleteWithoutId() =
        requestBearerToken().let {
            httpClient.delete("${config.registrationEndpoint}") {
                header("Authorization", "Bearer ${it.accessToken}")
            }
        }

    suspend fun deleteClient(clientId: String) =
        requestBearerToken().let {
            httpClient.delete("${config.registrationEndpoint}/$clientId") {
                header("Authorization", "Bearer ${it.accessToken}")
            }
        }

    suspend fun getClient(clientId: String): OAuth2Client? =
        requestBearerToken().let {
            httpClient.get("${config.registrationEndpoint}/$clientId") {
                header("Authorization", "Bearer ${it.accessToken}")
            }.body()
        }

    suspend fun getClients(): List<OAuth2Client> =
        requestBearerToken().let {
            httpClient.get(config.registrationEndpoint) {
                header("Authorization", "Bearer ${it.accessToken}")
            }.body()
        }

    private fun SoftwareStatement.sign(): String =
        SignedJWT(
            JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(config.signingKey.keyID)
                .type(JOSEObjectType.JWT).build(),
            JWTClaimsSet.parse(jacksonObjectMapper().writeValueAsString(this))
        ).apply {
            sign(RSASSASigner(config.signingKey.toPrivateKey()))
        }.serialize()

    private fun requestBearerToken(): OAuth2TokenResponse =
        runBlocking {
            val clientAssertion = createClientAssertion(
                config.jwkerClientId,
                config.identityProviderTokenEndpoint,
                config.signingKey
            )
            httpClient.submitForm(
                url = config.identityProviderTokenEndpoint,
                formParameters = parametersOf(
                    "client_assertion_type" to listOf("urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
                    "client_assertion" to listOf(clientAssertion),
                    "grant_type" to listOf("client_credentials"),
                    "scope" to listOf(config.bearerTokenScope)
                ),
                encodeInQuery = false
            ).body()
        }
}

private fun createJWK(): RSAKey =
    KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }
        .generateKeyPair()
        .let {
            RSAKey.Builder(it.public as RSAPublicKey)
                .privateKey(it.private as RSAPrivateKey)
                .keyID(UUID.randomUUID().toString())
                .build()
        }

private fun createClientAssertion(clientId: String, tokenEndpoint: String, rsaKey: RSAKey): String =
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
    }.serialize()

internal val httpClient = HttpClient(CIO) {
    install(io.ktor.client.plugins.contentnegotiation.ContentNegotiation) {
        jackson() {
            configure(FAIL_ON_UNKNOWN_PROPERTIES, false)
            setSerializationInclusion(JsonInclude.Include.NON_NULL)
        }
    }
}
