package io.nais.security.oauth2.config

import com.natpryce.konfig.ConfigurationProperties
import com.natpryce.konfig.EnvironmentVariables
import com.natpryce.konfig.Key
import com.natpryce.konfig.overriding
import com.natpryce.konfig.stringType
import io.ktor.client.request.get
import io.nais.security.oauth2.defaultHttpClient
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
    LOCAL,
    NON_PROD,
    PROD
}

fun configByProfile(): AppConfiguration =
    when (konfig.getOrNull(Key("APPLICATION_PROFILE", stringType))?.let { Profile.valueOf(it) }) {
        Profile.LOCAL -> LocalConfiguration.instance
        Profile.NON_PROD -> NonProdConfiguration.instance
        Profile.PROD -> ProdConfiguration.instance
        else -> ProdConfiguration.instance
    }

fun environmentDatabaseConfig(): DatabaseConfig =
    DatabaseConfig(
        konfig[Key("DB_URL", stringType)],
        konfig[Key("DB_USER", stringType)],
        konfig[Key("DB_PASSWORD", stringType)]
    )

object ProdConfiguration {
    val instance by lazy {
        val tokenIssuerProperties = AuthorizationServerProperties(
            issuerUrl = "https://token-exchange.nais.io",
            subjectTokenIssuers = listOf(
                SubjectTokenIssuer(
                    "https://login.microsoftonline.com/navnob2c.onmicrosoft.com/v2.0/.well-known/openid-configuration?p=B2C_1A_idporten"
                )
            )
        )
        val clientRegistry = ClientRegistry(
            ClientRegistryProperties(dataSourceFrom(environmentDatabaseConfig()).apply {
                migrate(this)
            })
        )
        AppConfiguration(ServerProperties(8080), clientRegistry, tokenIssuerProperties)
    }
}

object NonProdConfiguration {
    val instance by lazy {
        val tokenIssuerProperties = AuthorizationServerProperties(
            issuerUrl = "https://token-exchange.dev-gcp.nais.io",
            subjectTokenIssuers = listOf()
        )
        val clientRegistry = ClientRegistry(
            ClientRegistryProperties(dataSourceFrom(environmentDatabaseConfig()).apply {
                migrate(this)
            })
        )
        AppConfiguration(ServerProperties(8080), clientRegistry, tokenIssuerProperties)
    }
}

object LocalConfiguration {
    val instance by lazy {
        val tokenIssuerProperties = AuthorizationServerProperties(
            issuerUrl = "http://localhost:8080",
            subjectTokenIssuers = listOf()
        )
        val clientRegistry = ClientRegistry(
            ClientRegistryProperties(
                dataSourceFrom(
                    // requires docker instance of postgres
                    DatabaseConfig(
                        "jdbc:postgresql://localhost:5432/token-exchange",
                        "user",
                        "pwd"
                    )
                ).apply {
                    migrate(this)
                }
            )
        )
        AppConfiguration(ServerProperties(8080), clientRegistry, tokenIssuerProperties)
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
