package io.nais.security.oauth2.config

import com.auth0.jwk.JwkProvider
import com.auth0.jwk.JwkProviderBuilder
import com.nimbusds.jose.jwk.JWKSet
import io.ktor.client.request.get
import io.nais.security.oauth2.authentication.BearerTokenAuth
import io.nais.security.oauth2.defaultHttpClient
import io.nais.security.oauth2.model.WellKnown
import io.nais.security.oauth2.registration.ClientRegistry
import io.nais.security.oauth2.keystore.RsaKeyService
import io.nais.security.oauth2.token.TokenIssuer
import kotlinx.coroutines.runBlocking
import mu.KotlinLogging
import java.net.URL
import java.util.concurrent.TimeUnit
import javax.sql.DataSource

private val log = KotlinLogging.logger {}

data class AppConfiguration(
    val serverProperties: ServerProperties,
    val clientRegistry: ClientRegistry,
    val authorizationServerProperties: AuthorizationServerProperties,
    val clientRegistrationAuthProperties: ClientRegistrationAuthProperties
) {
    val tokenIssuer: TokenIssuer = TokenIssuer(authorizationServerProperties)
}

data class ServerProperties(val port: Int)

data class ClientRegistryProperties(
    val dataSource: DataSource
)

data class ClientRegistrationAuthProperties(
    val identityProviderWellKnownUrl: String,
    val acceptedAudience: List<String>,
    val acceptedRoles: List<String> = BearerTokenAuth.ACCEPTED_ROLES_CLAIM_VALUE,
    val softwareStatementJwks: JWKSet
) {
    val wellKnown: WellKnown = runBlocking {
        log.info("getting OpenID Connect server metadata from well-known url=$identityProviderWellKnownUrl")
        defaultHttpClient.get<WellKnown>(identityProviderWellKnownUrl)
    }
    val jwkProvider: JwkProvider = JwkProviderBuilder(URL(wellKnown.jwksUri))
        .cached(10, 24, TimeUnit.HOURS)
        .rateLimited(10, 1, TimeUnit.MINUTES)
        .build()
}

class AuthorizationServerProperties(
    val issuerUrl: String,
    val subjectTokenIssuers: List<SubjectTokenIssuer>,
    val tokenExpiry: Long = 300,
    val keyStoreService: RsaKeyService,
    val clientAssertionMaxExpiry: Long = 120
) {
    fun tokenEndpointUrl() = issuerUrl.path(tokenPath)
    fun clientRegistrationUrl() = issuerUrl.path(registrationPath)

    companion object {
        const val wellKnownPath = "/.well-known/oauth-authorization-server"
        const val authorizationPath = "/authorization"
        const val tokenPath = "/token"
        const val jwksPath = "/jwks"
        const val registrationPath = "/registration/client"
    }
}

class SubjectTokenIssuer(private val wellKnownUrl: String) {
    val wellKnown: WellKnown = runBlocking {
        log.info("getting OAuth2 server metadata from well-known url=$wellKnownUrl")
        defaultHttpClient.get<WellKnown>(wellKnownUrl)
    }
    val issuer = wellKnown.issuer
}

data class RsaKeyStoreProperties(
    val dataSource: DataSource,
    val rotationInterval: Long
)

fun String.path(path: String) = "${this.removeSuffix("/")}/${path.removePrefix("/")}"
