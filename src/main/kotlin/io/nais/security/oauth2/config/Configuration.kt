package io.nais.security.oauth2.config

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.databind.DeserializationFeature
import com.natpryce.konfig.ConfigurationProperties
import com.natpryce.konfig.EnvironmentVariables
import com.natpryce.konfig.Key
import com.natpryce.konfig.intType
import com.natpryce.konfig.overriding
import com.natpryce.konfig.stringType
import io.ktor.client.HttpClient
import io.ktor.client.engine.apache.Apache
import io.ktor.client.features.json.JacksonSerializer
import io.ktor.client.features.json.JsonFeature
import io.ktor.client.request.get
import io.nais.security.oauth2.model.WellKnown
import kotlinx.coroutines.runBlocking
import mu.KotlinLogging
import org.apache.http.impl.conn.SystemDefaultRoutePlanner
import java.net.ProxySelector

internal val defaultHttpClient = HttpClient(Apache) {
    install(JsonFeature) {
        serializer = JacksonSerializer {
            configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
            setSerializationInclusion(JsonInclude.Include.NON_NULL)
        }
    }
    engine {
        customizeClient { setRoutePlanner(SystemDefaultRoutePlanner(ProxySelector.getDefault())) }
    }
}

private val config = ConfigurationProperties.systemProperties() overriding
    EnvironmentVariables() overriding
    ConfigurationProperties.fromResource("application.properties")

private val log = KotlinLogging.logger {}

data class Configuration(
    val application: Application = Application(),
    val tokenIssuerConfig: TokenIssuerConfig = TokenIssuerConfig(application.ingress),
    val tokenValidatorConfig: TokenValidatorConfig = TokenValidatorConfig(emptyList())
) {

    data class Application(
        val port: Int = config[Key("application.port", intType)],
        val name: String = config[Key("application.name", stringType)],
        val ingress: String = config[Key("application.ingress", stringType)]
    )
}

data class TokenValidatorConfig(private val externalIssuerDiscoveryUrls: List<String>) {

    val issuerToWellKnownMap: Map<String, WellKnown> = externalIssuerDiscoveryUrls.asSequence()
        .map {
            runBlocking {
                log.info("getting OAuth2 server metadata from well-known url=$it")
                defaultHttpClient.get<WellKnown>(it)
            }
        }.associateBy { it.issuer }
}

// TODO keys with expiration?
data class TokenIssuerConfig(val issuerUrl: String) {

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
