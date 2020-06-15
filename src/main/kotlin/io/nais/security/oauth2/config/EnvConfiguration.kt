package io.nais.security.oauth2.config

import com.natpryce.konfig.ConfigurationProperties
import com.natpryce.konfig.EnvironmentVariables
import com.natpryce.konfig.Key
import com.natpryce.konfig.enumType
import com.natpryce.konfig.listType
import com.natpryce.konfig.overriding
import com.natpryce.konfig.stringType
import com.nimbusds.jose.jwk.JWKSet
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
import io.nais.security.oauth2.registration.ClientRegistry
import io.nais.security.oauth2.token.DefaultKeyStore
import io.nais.security.oauth2.token.KeyStore

val konfig = ConfigurationProperties.systemProperties() overriding
    EnvironmentVariables()

enum class Profile {
    NON_PROD,
    PROD
}

internal object EnvKey {
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

object ProdConfiguration {
    val instance by lazy {
        val authorizationServerProperties = AuthorizationServerProperties(
            issuerUrl = "https://tokendings.prod-gcp.nais.io",
            subjectTokenIssuers = listOf(),
            keyStore = keyStore()
        )
        val clientRegistry = clientRegistry()
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
                ),
                SubjectTokenIssuer("https://oidc-ver2.difi.no/idporten-oidc-provider/.well-known/openid-configuration")
            ),
            keyStore = keyStore()
        )
        val clientRegistry = clientRegistry()
        val bearerTokenAuthenticationProperties = clientRegistrationAuthProperties()
        AppConfiguration(ServerProperties(8080), clientRegistry, authorizationServerProperties, bearerTokenAuthenticationProperties)
    }
}

fun configByProfile(): AppConfiguration =
    when (konfig.getOrNull(Key(APPLICATION_PROFILE, enumType<Profile>()))) {
        Profile.NON_PROD -> NonProdConfiguration.instance
        Profile.PROD -> ProdConfiguration.instance
        else -> ProdConfiguration.instance
    }

fun AppConfiguration.isNonProd() = Profile.PROD != konfig.getOrNull(Key(APPLICATION_PROFILE, enumType<Profile>()))

internal fun databaseConfig(): DatabaseConfig {
    val hostname = konfig[Key(DB_HOST, stringType)]
    val port = konfig[Key(DB_PORT, stringType)]
    val name = konfig[Key(DB_DATABASE, stringType)]
    return DatabaseConfig(
        "jdbc:postgresql://$hostname:$port/$name",
        konfig[Key(DB_USERNAME, stringType)],
        konfig[Key(DB_PASSWORD, stringType)]
    )
}

internal fun keyStore(): KeyStore =
    DefaultKeyStore(
        konfig[Key(PRIVATE_JWKS, stringType)].let {
            JWKSet.parse(it)
        }
    )

internal fun clientRegistrationAuthProperties(): ClientRegistrationAuthProperties =
    ClientRegistrationAuthProperties(
        identityProviderWellKnownUrl = "https://login.microsoftonline.com/62366534-1ec3-4962-8869-9b5535279d0b/v2.0/.well-known/openid-configuration",
        acceptedAudience = konfig[Key(AUTH_ACCEPTED_AUDIENCE, listType(stringType, Regex(",")))],
        requiredClaims = mapOf("roles" to "access_as_application"),
        softwareStatementJwks = konfig[Key(AUTH_JWKER_JWKS, stringType)].let {
            JWKSet.parse(it)
        }
    )

internal fun clientRegistry(): ClientRegistry =
    ClientRegistry(
        ClientRegistryProperties(
            dataSourceFrom(databaseConfig()).apply {
                migrate(this)
            }
        )
    )
