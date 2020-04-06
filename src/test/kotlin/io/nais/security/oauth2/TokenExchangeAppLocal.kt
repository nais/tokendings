package io.nais.security.oauth2

import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jwt.JWTClaimsSet
import io.ktor.application.call
import io.ktor.response.respond
import io.ktor.routing.get
import io.ktor.routing.route
import io.ktor.routing.routing
import io.ktor.util.KtorExperimentalAPI
import io.nais.security.oauth2.authentication.ClientRegistry
import io.nais.security.oauth2.authentication.OAuth2Client
import io.nais.security.oauth2.config.Configuration
import io.nais.security.oauth2.config.TokenIssuerConfig
import io.nais.security.oauth2.config.TokenValidatorConfig
import io.nais.security.oauth2.config.path
import io.nais.security.oauth2.token.JwtTokenProvider
import io.nais.security.oauth2.token.JwtTokenProvider.Companion.createSignedJWT
import io.nais.security.oauth2.token.JwtTokenProvider.Companion.generateJWKSet
import mu.KotlinLogging
import no.nav.security.mock.oauth2.MockOAuth2Server
import no.nav.security.mock.oauth2.OAuth2Config
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.Date
import java.util.UUID
import java.util.concurrent.TimeUnit

val log = KotlinLogging.logger {  }

@KtorExperimentalAPI
fun main() {
    val mockOAuth2Server = MockOAuth2Server(
        OAuth2Config(
            interactiveLogin = true
        )
    ).apply {
        this.start(1111)
    }

    val app = Configuration.Application()

    val config = Configuration(
        application = app,
        tokenIssuerConfig = TokenIssuerConfig(
            app.ingress,
            oauth2Clients(app)
        ),
        tokenValidatorConfig = TokenValidatorConfig(listOf(mockOAuth2Server.wellKnownUrl("mock").toString()))
    )
   tokenExchangeApp(config, DefaultRouting(config)).start(wait = true)
}

private fun oauth2Clients(app: Configuration.Application): List<OAuth2Client> {
    val clientId = "local:client"
    val keyId = "localkey"
    val jwkSet = generateJWKSet(keyId, 2048)
        .also {
            val clientAssertion = createSignedJWT(
                JWTClaimsSet.Builder()
                    .issuer(clientId)
                    .subject(clientId)
                    .audience(app.ingress.path(TokenIssuerConfig.tokenPath))
                    .issueTime(Date.from(Instant.now()))
                    .expirationTime(Date.from(Instant.now().plus(365, ChronoUnit.DAYS)))
                    .jwtID(UUID.randomUUID().toString())
                    .build(),
                it.getKeyByKeyId(keyId) as RSAKey
            )
            log.info("addded default OAuth2Client with client_id=$clientId and generated client_assertion=${clientAssertion.serialize()}")
        }
    return listOf(OAuth2Client(clientId, jwkSet.toPublicJWKSet()))
}




