package io.nais.security.oauth2.config

import com.auth0.jwk.JwkProvider
import com.auth0.jwk.JwkProviderBuilder
import com.natpryce.konfig.ConfigurationProperties
import com.natpryce.konfig.EnvironmentVariables
import com.natpryce.konfig.Key
import com.natpryce.konfig.listType
import com.natpryce.konfig.overriding
import com.natpryce.konfig.stringType
import com.nimbusds.jose.jwk.JWKSet
import io.ktor.client.request.get
import io.nais.security.oauth2.config.EnvKey.APPLICATION_PROFILE
import io.nais.security.oauth2.config.EnvKey.AUTH_ACCEPTED_AUDIENCE
import io.nais.security.oauth2.config.EnvKey.AUTH_JWKER_JWKS
import io.nais.security.oauth2.config.EnvKey.AUTH_JWKER_SUB
import io.nais.security.oauth2.config.EnvKey.DB_DATABASE
import io.nais.security.oauth2.config.EnvKey.DB_HOST
import io.nais.security.oauth2.config.EnvKey.DB_PASSWORD
import io.nais.security.oauth2.config.EnvKey.DB_PORT
import io.nais.security.oauth2.config.EnvKey.DB_USERNAME
import io.nais.security.oauth2.config.EnvKey.PRIVATE_JWKS
import io.nais.security.oauth2.defaultHttpClient
import io.nais.security.oauth2.model.WellKnown
import io.nais.security.oauth2.registration.ClientRegistry
import io.nais.security.oauth2.token.DefaultKeyStore
import io.nais.security.oauth2.token.KeyStore
import io.nais.security.oauth2.token.TokenIssuer
import kotlinx.coroutines.runBlocking
import mu.KotlinLogging
import java.net.URL
import java.util.concurrent.TimeUnit
import javax.sql.DataSource

private val log = KotlinLogging.logger {}

val konfig = ConfigurationProperties.systemProperties() overriding
    EnvironmentVariables()

enum class Profile {
    NON_PROD,
    PROD
}

object EnvKey {
    const val APPLICATION_PROFILE = "APPLICATION_PROFILE"
    const val DB_HOST = "DB_HOST"
    const val DB_PORT = "DB_PORT"
    const val DB_DATABASE = "DB_DATABASE"
    const val DB_USERNAME = "DB_USERNAME"
    const val DB_PASSWORD = "DB_PASSWORD"
    const val AUTH_ACCEPTED_AUDIENCE = "AUTH_ACCEPTED_AUDIENCE"
    const val AUTH_JWKER_SUB = "AUTH_JWKER_SUB"
    const val AUTH_JWKER_JWKS = "AUTH_JWKER_JWKS"
    const val PRIVATE_JWKS = "PRIVATE_JWKS"
}

fun configByProfile(): AppConfiguration =
    when (konfig.getOrNull(Key(APPLICATION_PROFILE, stringType))?.let { Profile.valueOf(it) }) {
        Profile.NON_PROD -> NonProdConfiguration.instance
        Profile.PROD -> ProdConfiguration.instance
        else -> ProdConfiguration.instance
    }

fun environmentDatabaseConfig(): DatabaseConfig {
    val hostname = konfig[Key(DB_HOST, stringType)]
    val port = konfig[Key(DB_PORT, stringType)]
    val name = konfig[Key(DB_DATABASE, stringType)]
    return DatabaseConfig(
        "jdbc:postgresql://$hostname:$port/$name",
        konfig[Key(DB_USERNAME, stringType)],
        konfig[Key(DB_PASSWORD, stringType)]
    )
}

fun keyStoreFromEnv(): KeyStore =
    DefaultKeyStore(konfig[Key(PRIVATE_JWKS, stringType)].let {
        JWKSet.parse(it)
    })

fun clientRegistrationAuthProperties(): ClientRegistrationAuthProperties =
    ClientRegistrationAuthProperties(
        identityProviderWellKnownUrl = "https://login.microsoftonline.com/62366534-1ec3-4962-8869-9b5535279d0b/v2.0/.well-known/openid-configuration",
        acceptedAudience = konfig[Key(AUTH_ACCEPTED_AUDIENCE, listType(stringType, Regex(",")))],
        requiredClaims = mapOf("sub" to konfig[Key(AUTH_JWKER_SUB, stringType)]),
        softwareStatementJwks = konfig[Key(AUTH_JWKER_JWKS, stringType)].let {
            JWKSet.parse(it)
        }
    )

fun clientRegistryFromEnvironment(): ClientRegistry =
    ClientRegistry(
        ClientRegistryProperties(dataSourceFrom(environmentDatabaseConfig()).apply {
            migrate(this)
        })
    )

object ProdConfiguration {
    val instance by lazy {
        val authorizationServerProperties = AuthorizationServerProperties(
            issuerUrl = "https://tokendings.prod-gcp.nais.io",
            subjectTokenIssuers = listOf(),
            keyStore = keyStoreFromEnv()
        )
        val clientRegistry = clientRegistryFromEnvironment()
        val bearerTokenAuthenticationProperties = clientRegistrationAuthProperties()
        AppConfiguration(ServerProperties(8080), clientRegistry, authorizationServerProperties, bearerTokenAuthenticationProperties)
    }
}

object NonProdConfiguration {
    val instance by lazy {
        val authorizationServerProperties = AuthorizationServerProperties(
            issuerUrl = "https://tokendings.dev-gcp.nais.io",
            subjectTokenIssuers = listOf(
                SubjectTokenIssuer(
                    "https://login.microsoftonline.com/NAVtestB2C.onmicrosoft.com/v2.0/.well-known/openid-configuration?p=B2C_1A_idporten_ver1"
                )
            ),
            keyStore = keyStoreFromEnv()
        )
        val clientRegistry = clientRegistryFromEnvironment()
        val bearerTokenAuthenticationProperties = clientRegistrationAuthProperties()
        AppConfiguration(ServerProperties(8080), clientRegistry, authorizationServerProperties, bearerTokenAuthenticationProperties)
    }
}

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
    val requiredClaims: Map<String, String> = emptyMap(),
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
    val keyStore: KeyStore
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

fun String.path(path: String) = "${this.removeSuffix("/")}/${path.removePrefix("/")}"
