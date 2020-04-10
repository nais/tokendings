package io.nais.security.oauth2.config

import com.natpryce.konfig.ConfigurationMap
import com.natpryce.konfig.ConfigurationProperties.Companion.systemProperties
import com.natpryce.konfig.EnvironmentVariables
import com.natpryce.konfig.Key
import com.natpryce.konfig.intType
import com.natpryce.konfig.overriding
import com.natpryce.konfig.stringType
import io.ktor.client.request.get
import io.nais.security.oauth2.authentication.ClientRegistry
import io.nais.security.oauth2.authentication.OAuth2Client
import io.nais.security.oauth2.config.ConfigKeys.APPLICATION_INGRESS
import io.nais.security.oauth2.config.ConfigKeys.APPLICATION_PORT
import io.nais.security.oauth2.config.ConfigKeys.APPLICATION_PROFILE
import io.nais.security.oauth2.defaultHttpClient
import io.nais.security.oauth2.model.WellKnown
import io.nais.security.oauth2.token.TokenIssuer
import kotlinx.coroutines.runBlocking
import mu.KotlinLogging

// TODO ensure local props cannot be enabled in prod
private val config =
    systemProperties() overriding
        EnvironmentVariables() overriding
        localProperties()
// fromResource("application.properties")

private val log = KotlinLogging.logger {}

private const val appName = "tokendings"

object ConfigKeys {
    const val APPLICATION_PROFILE = "$appName.profile"
    const val APPLICATION_PORT = "$appName.port"
    const val APPLICATION_INGRESS = "$appName.ingress"
}

private fun localProperties() = ConfigurationMap(
    mapOf(
        APPLICATION_PROFILE to Profile.LOCAL.toString(),
        APPLICATION_PORT to "8080",
        APPLICATION_INGRESS to "http://localhost:8080"
    )
)

enum class Profile {
    LOCAL,
    DEV,
    PROD
}

class Configuration(
    val serverConfig: ServerConfig = ServerConfig(),
    val tokenValidatorConfig: TokenValidatorConfig = TokenValidatorConfig(serverConfig.profile),
    val tokenIssuerConfig: TokenIssuerConfig = TokenIssuerConfig(serverConfig.ingress, tokenValidatorConfig)
) {

    data class ServerConfig(
        val profile: Profile = config[Key(APPLICATION_PROFILE, stringType)].let { Profile.valueOf(it) },
        val port: Int = config[Key(APPLICATION_PORT, intType)],
        val ingress: String = config[Key(APPLICATION_INGRESS, stringType)]
    )

    private fun tokenValidatorConfig(profile: Profile): TokenValidatorConfig =
        when (profile) {
            Profile.LOCAL -> TokenValidatorConfig(listOf())
            Profile.DEV -> TokenValidatorConfig(listOf())
            else -> TokenValidatorConfig(listOf())
        }
}

data class TokenValidatorConfig(private val externalIssuerDiscoveryUrls: List<String>) {

    constructor(profile: Profile) : this(
        when (profile) {
            Profile.LOCAL -> listOf<String>()
            Profile.DEV -> listOf<String>()
            else -> listOf<String>()
        }
    )

    val issuerToWellKnownMap: Map<String, WellKnown> = externalIssuerDiscoveryUrls.asSequence()
        .map {
            runBlocking {
                log.info("getting OAuth2 server metadata from well-known url=$it")
                defaultHttpClient.get<WellKnown>(it)
            }
        }.associateBy { it.issuer }
}

// TODO keys with expiration?
data class TokenIssuerConfig(
    val issuerUrl: String,
    val tokenValidatorConfig: TokenValidatorConfig,
    val clientRegistry: ClientRegistry = ClientRegistry(issuerUrl.path(tokenPath), listOf())
) {
    val tokenIssuer: TokenIssuer = TokenIssuer(issuerUrl, tokenValidatorConfig)

    val wellKnown: WellKnown = WellKnown(
        issuer = issuerUrl,
        authorizationEndpoint = issuerUrl.path(authorizationPath),
        tokenEndpoint = issuerUrl.path(tokenPath),
        jwksUri = issuerUrl.path(jwksPath)
    )

    companion object {
        const val wellKnownPath = "/.well-known/oauth-authorization-server"
        const val authorizationPath = "/authorization"
        const val tokenPath = "/token"
        const val jwksPath = "/jwks"
    }
}

fun String.path(path: String) = "${this.removeSuffix("/")}/${path.removePrefix("/")}"
