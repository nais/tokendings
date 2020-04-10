package io.nais.security.oauth2.mock

import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod
import io.ktor.application.Application
import io.ktor.application.call
import io.ktor.auth.Credential
import io.ktor.request.receive
import io.ktor.response.respond
import io.ktor.routing.Routing
import io.ktor.routing.post
import io.ktor.routing.routing
import io.ktor.util.KtorExperimentalAPI
import io.nais.security.oauth2.DefaultRouting
import io.nais.security.oauth2.authentication.AccessPolicy
import io.nais.security.oauth2.authentication.ClientAuthenticationPrincipal
import io.nais.security.oauth2.authentication.ClientRegistry
import io.nais.security.oauth2.authentication.OAuth2Client
import io.nais.security.oauth2.config.Configuration
import io.nais.security.oauth2.config.TokenIssuerConfig
import io.nais.security.oauth2.config.TokenIssuerConfig.Companion.tokenPath
import io.nais.security.oauth2.config.TokenValidatorConfig
import io.nais.security.oauth2.config.path
import io.nais.security.oauth2.token.JwtTokenProvider.Companion.createSignedJWT
import io.nais.security.oauth2.token.JwtTokenProvider.Companion.generateJWKSet
import io.nais.security.oauth2.tokenExchangeApp
import mu.KotlinLogging
import no.nav.security.mock.oauth2.MockOAuth2Server
import no.nav.security.mock.oauth2.OAuth2Config
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.Date
import java.util.UUID

val log = KotlinLogging.logger { }

@KtorExperimentalAPI
fun main() {
    val mockOAuth2Server: MockOAuth2Server = startMockOAuth2Server()


    val serverConfig = Configuration.ServerConfig()
    val tokenValidatorConfig = TokenValidatorConfig(listOf(mockOAuth2Server.wellKnownUrl("mock").toString()))
    val clientRegistry = MockClientRegistry(serverConfig.ingress.path(tokenPath))
    val tokenIssuerConfig = TokenIssuerConfig(serverConfig.ingress, tokenValidatorConfig, clientRegistry)
    val config = Configuration(
        serverConfig = serverConfig,
        tokenValidatorConfig = tokenValidatorConfig,
        tokenIssuerConfig = tokenIssuerConfig
    )

    tokenExchangeApp(config, MockApiRouting(config)).start(wait = true)
}

class MockClientRegistry(acceptedAudience: String) : ClientRegistry(acceptedAudience, emptyList()) {
    override fun authenticate(credential: Credential): ClientAuthenticationPrincipal? {
        return ClientAuthenticationPrincipal(
            oauth2Client("dummy"),
            ClientAuthenticationMethod.PRIVATE_KEY_JWT
        )
    }
}

class MockApiRouting(private val config: Configuration) : DefaultRouting(config) {
    override fun apiRouting(application: Application): Routing {
        return application.routing {
            super.apiRouting(application)
            clientRegistrationApi(config)

            post("yolo") {
                call.respond(call.receive<String>())
            }

        }
    }
}

private fun oauth2Client(clientId: String): OAuth2Client {
    val keyId = "localkey"
    val jwkSet = generateJWKSet(keyId, 2048)
    return OAuth2Client(clientId, jwkSet.toPublicJWKSet(), AccessPolicy())
}

private fun oauth2Clients(serverConfig: Configuration.ServerConfig): List<OAuth2Client> {
    val clientId = "local:client"
    val keyId = "localkey"
    val jwkSet = generateJWKSet(keyId, 2048)
        .also {
            val clientAssertion = createSignedJWT(
                JWTClaimsSet.Builder()
                    .issuer(clientId)
                    .subject(clientId)
                    .audience(serverConfig.ingress.path(TokenIssuerConfig.tokenPath))
                    .issueTime(Date.from(Instant.now()))
                    .expirationTime(Date.from(Instant.now().plus(365, ChronoUnit.DAYS)))
                    .jwtID(UUID.randomUUID().toString())
                    .build(),
                it.getKeyByKeyId(keyId) as RSAKey
            )
            log.info("added default OAuth2Client with client_id=$clientId and generated client_assertion=${clientAssertion.serialize()}")
        }
    return listOf(OAuth2Client(clientId, jwkSet.toPublicJWKSet(), AccessPolicy()))
}

private fun startMockOAuth2Server(): MockOAuth2Server =
    MockOAuth2Server(
        OAuth2Config(
            interactiveLogin = true
        )
    ).apply {
        this.start(1111)
    }
