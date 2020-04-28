package io.nais.security.oauth2.config

import com.fasterxml.jackson.module.kotlin.readValue
import com.natpryce.konfig.ConfigurationProperties
import com.natpryce.konfig.EnvironmentVariables
import com.natpryce.konfig.Key
import com.natpryce.konfig.overriding
import com.natpryce.konfig.stringType
import io.ktor.client.request.get
import io.nais.security.oauth2.Jackson
import io.nais.security.oauth2.defaultHttpClient
import io.nais.security.oauth2.model.ClientId
import io.nais.security.oauth2.model.GrantType
import io.nais.security.oauth2.model.JsonWebKeys
import io.nais.security.oauth2.model.OAuth2Client
import io.nais.security.oauth2.model.WellKnown
import io.nais.security.oauth2.registration.ClientRegistry
import io.nais.security.oauth2.token.TokenIssuer
import kotlinx.coroutines.runBlocking
import mu.KotlinLogging
import javax.sql.DataSource

private val log = KotlinLogging.logger {}

val konfig =
    ConfigurationProperties.systemProperties() overriding
        EnvironmentVariables()

enum class Profile {
    NON_PROD,
    PROD
}

fun configByProfile(): AppConfiguration =
    when (konfig.getOrNull(Key("APPLICATION_PROFILE", stringType))?.let { Profile.valueOf(it) }) {
        Profile.NON_PROD -> NonProdConfiguration.instance
        Profile.PROD -> ProdConfiguration.instance
        else -> ProdConfiguration.instance
    }

fun environmentDatabaseConfig(): DatabaseConfig {
    val hostname = konfig[Key("DB_HOST", stringType)]
    val port = konfig[Key("DB_PORT", stringType)]
    val name = konfig[Key("DB_DATABASE", stringType)]
    return DatabaseConfig(
        "jdbc:postgresql://$hostname:$port/$name",
        konfig[Key("DB_USERNAME", stringType)],
        konfig[Key("DB_PASSWORD", stringType)]
    )
}

fun clientRegistryFromEnvironment(): ClientRegistry =
    ClientRegistry(
        ClientRegistryProperties(dataSourceFrom(environmentDatabaseConfig()).apply {
            migrate(this)
        })
    )

fun ClientRegistry.bootstrapAdminClients(
    authorizationServerProperties: AuthorizationServerProperties,
    bootstrapClientProperties: List<BootstrapClientProperties>
) = bootstrapClientProperties.forEach {
    if (this.findClient(it.clientId) == null) {
        this.registerClient(
            OAuth2Client(
                clientId = it.clientId,
                jwks = it.jwks,
                allowedScopes = listOf(authorizationServerProperties.clientRegistrationUrl()),
                allowedGrantTypes = listOf(GrantType.CLIENT_CREDENTIALS_GRANT)
            )
        )
    }
}

object ProdConfiguration {
    val instance by lazy {
        val authorizationServerProperties = AuthorizationServerProperties(
            issuerUrl = "https://token-exchange.nais.io",
            subjectTokenIssuers = listOf()
        )
        val clientRegistry = clientRegistryFromEnvironment()
        AppConfiguration(ServerProperties(8080), clientRegistry, authorizationServerProperties)
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
            )
        )
        val clientRegistry = clientRegistryFromEnvironment()
        AppConfiguration(ServerProperties(8080), clientRegistry, authorizationServerProperties)
    }
}

data class AppConfiguration(
    val serverProperties: ServerProperties,
    val clientRegistry: ClientRegistry,
    val authorizationServerProperties: AuthorizationServerProperties
) {
    val tokenIssuer: TokenIssuer = TokenIssuer(authorizationServerProperties)
}

data class ServerProperties(val port: Int)

data class ClientRegistryProperties(
    val dataSource: DataSource
)

data class BootstrapClientProperties(
    val clientId: ClientId,
    val clientJwksUri: String
) {
    val jwks: JsonWebKeys by lazy {
        runBlocking {
            log.info("getting keys for bootstrap client from jwks uri=$clientJwksUri")
            // TODO: figure out why JsonWebKeys cant be deserialized directly.....
            val string: String = defaultHttpClient.get<String>(clientJwksUri)
            Jackson.defaultMapper.readValue<JsonWebKeys>(string)
        }
    }
}

class AuthorizationServerProperties(
    val issuerUrl: String,
    val subjectTokenIssuers: List<SubjectTokenIssuer>,
    val tokenExpiry: Long = 300,
    val keySize: Int = 2048
) {

    fun wellKnownUrl() = issuerUrl.path(wellKnownPath)
    fun authorizationEndpointUrl() = issuerUrl.path(authorizationPath)
    fun tokenEndpointUrl() = issuerUrl.path(tokenPath)
    fun jwksUri() = issuerUrl.path(jwksPath)
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
