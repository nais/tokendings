package io.nais.security.oauth2.config

import com.codahale.metrics.MetricRegistry
import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import com.natpryce.konfig.ConfigurationProperties
import com.natpryce.konfig.EnvironmentVariables
import com.natpryce.konfig.Key
import com.natpryce.konfig.enumType
import com.natpryce.konfig.intType
import com.natpryce.konfig.listType
import com.natpryce.konfig.longType
import com.natpryce.konfig.overriding
import com.natpryce.konfig.stringType
import com.nimbusds.jose.jwk.JWKSet
import io.nais.security.oauth2.config.EnvKey.APPLICATION_PORT
import io.nais.security.oauth2.config.EnvKey.APPLICATION_PROFILE
import io.nais.security.oauth2.config.EnvKey.AUTH_ACCEPTED_AUDIENCE
import io.nais.security.oauth2.config.EnvKey.AUTH_CLIENT_ID
import io.nais.security.oauth2.config.EnvKey.AUTH_CLIENT_JWKS
import io.nais.security.oauth2.config.EnvKey.AUTH_PROVIDER_CONFIGS
import io.nais.security.oauth2.config.EnvKey.AUTH_WELL_KNOWN_URL
import io.nais.security.oauth2.config.EnvKey.DB_JDBC_URL
import io.nais.security.oauth2.config.EnvKey.DEFAULT_TOKEN_EXPIRY_SECONDS
import io.nais.security.oauth2.config.EnvKey.FEDERATED_CLIENT_AUTH_AUDIENCE
import io.nais.security.oauth2.config.EnvKey.FEDERATED_CLIENT_AUTH_ISSUERS
import io.nais.security.oauth2.config.EnvKey.FEDERATED_CLIENT_AUTH_MAX_LIFETIME_SECONDS
import io.nais.security.oauth2.config.EnvKey.ISSUER_URL
import io.nais.security.oauth2.config.EnvKey.SUBJECT_TOKEN_ISSUERS
import io.nais.security.oauth2.config.EnvKey.SUBJECT_TOKEN_MAPPINGS
import io.nais.security.oauth2.config.EnvKey.TOKEN_EXPIRY_SECONDS
import io.nais.security.oauth2.model.IssuerClaimMappings
import io.nais.security.oauth2.model.issuerClaimMappingsFromJson
import mu.KotlinLogging
import java.io.File
import java.time.Duration

private val log = KotlinLogging.logger {}

val konfig =
    run {
        val base = ConfigurationProperties.systemProperties() overriding EnvironmentVariables()
        val localEnvFile = File("local.env")
        if (localEnvFile.exists()) {
            base overriding ConfigurationProperties.fromFile(localEnvFile)
        } else {
            base
        }
    }

enum class Profile {
    NON_PROD,
    PROD,
}

internal object EnvKey {
    const val APPLICATION_PROFILE = "APPLICATION_PROFILE"
    const val DB_JDBC_URL = "DB_JDBC_URL"
    const val AUTH_ACCEPTED_AUDIENCE = "AUTH_ACCEPTED_AUDIENCE"
    const val AUTH_WELL_KNOWN_URL = "AUTH_WELL_KNOWN_URL"
    const val AUTH_PROVIDER_CONFIGS = "AUTH_PROVIDER_CONFIGS"
    const val AUTH_CLIENT_JWKS = "AUTH_CLIENT_JWKS"
    const val AUTH_CLIENT_ID = "AUTH_CLIENT_ID"
    const val APPLICATION_PORT = "APPLICATION_PORT"
    const val TOKEN_EXPIRY_SECONDS = "TOKEN_EXPIRY_SECONDS"
    const val DEFAULT_TOKEN_EXPIRY_SECONDS = 900L
    const val ISSUER_URL = "ISSUER_URL"
    const val SUBJECT_TOKEN_ISSUERS = "SUBJECT_TOKEN_ISSUERS"
    const val SUBJECT_TOKEN_MAPPINGS = "SUBJECT_TOKEN_MAPPINGS"
    const val FEDERATED_CLIENT_AUTH_ISSUERS = "FEDERATED_CLIENT_AUTH_ISSUERS"
    const val FEDERATED_CLIENT_AUTH_AUDIENCE = "FEDERATED_CLIENT_AUTH_AUDIENCE"
    const val FEDERATED_CLIENT_AUTH_MAX_LIFETIME_SECONDS = "FEDERATED_CLIENT_AUTH_MAX_LIFETIME_SECONDS"
}

@JsonIgnoreProperties(ignoreUnknown = true)
data class AuthProviderConfig(
    @JsonProperty("wellKnownUrl") val wellKnownUrl: String,
    @JsonProperty("allowedClusterName") val allowedClusterName: String? = null,
    @JsonProperty("allowedSubjects") val allowedSubjects: List<String> = emptyList(),
)

object Configuration {
    private val issuerUrl = konfig[Key(ISSUER_URL, stringType)]
    private val subjectTokenIssuers = konfig[Key(SUBJECT_TOKEN_ISSUERS, stringType)].split(",").map { it.trim() }
    private val subjectTokenIssuerMappings: IssuerClaimMappings =
        konfig.getOrNull(Key(SUBJECT_TOKEN_MAPPINGS, stringType))?.let {
            issuerClaimMappingsFromJson(it)
        } ?: emptyMap()
    val instance by lazy {
        val metricRegistry = MetricRegistry()
        val databaseConfig = migrate(databaseConfig(metricRegistry))
        val authorizationServerProperties =
            AuthorizationServerProperties(
                issuerUrl = issuerUrl,
                subjectTokenIssuers = subjectTokenIssuers.toIssuerConfiguration(subjectTokenIssuerMappings),
                rotatingKeyStore =
                    rotatingKeyStore(
                        dataSource = databaseConfig,
                        rotationInterval = Duration.ofDays(1),
                    ),
                tokenExpiry = konfig.getOrElse(Key(TOKEN_EXPIRY_SECONDS, longType), DEFAULT_TOKEN_EXPIRY_SECONDS),
            )
        val clientRegistry = clientRegistry(databaseConfig)
        val databaseHealthCheck = databaseHealthCheck(databaseConfig)
        val bearerTokenAuthenticationProperties = clientRegistrationAuthProperties()
        AppConfiguration(
            ServerProperties(konfig[Key(APPLICATION_PORT, intType)]),
            clientRegistry,
            authorizationServerProperties,
            bearerTokenAuthenticationProperties,
            federatedClientAuthProperties(),
            databaseHealthCheck,
        )
    }
}

fun List<String>.toIssuerConfiguration(subjectTokenIssuerMappings: IssuerClaimMappings) =
    this
        .map { issuerWellKnown ->
            SubjectTokenIssuer(issuerWellKnown, subjectTokenIssuerMappings[issuerWellKnown] ?: emptyMap())
        }

fun configByProfile(): AppConfiguration =
    when (konfig.getOrNull(Key(APPLICATION_PROFILE, enumType<Profile>()))) {
        Profile.NON_PROD -> Configuration.instance
        Profile.PROD -> Configuration.instance
        else -> Configuration.instance
    }

@Suppress("unused")
fun isNonProd() = Profile.PROD != konfig.getOrNull(Key(APPLICATION_PROFILE, enumType<Profile>()))

internal fun databaseConfig(metricRegistry: MetricRegistry): DatabaseConfig =
    DatabaseConfig(
        konfig[Key(DB_JDBC_URL, stringType)],
        metricRegistry,
    )

fun clientRegistrationAuthProperties(): ClientRegistrationAuthProperties {
    val jwks =
        konfig[Key(AUTH_CLIENT_JWKS, stringType)].let { JWKSet.parse(it) }.also { jwkSet ->
            log.info("loaded ${jwkSet.keys.size} keys from AUTH_CLIENT_JWKS with key IDs: ${jwkSet.keys.map { it.keyID }}")
        }

    val providerConfigsJson = konfig.getOrNull(Key(AUTH_PROVIDER_CONFIGS, stringType))
    val wellknownUrl = konfig.getOrNull(Key(AUTH_WELL_KNOWN_URL, stringType))

    val providers =
        when {
            providerConfigsJson != null -> {
                log.debug("using external auth providers from AUTH_PROVIDER_CONFIGS")
                val configs: List<AuthProviderConfig> = jacksonObjectMapper().readValue(providerConfigsJson)
                configs
                    .map { config ->
                        AuthProvider.fromWellKnown(
                            wellKnownUrl = config.wellKnownUrl,
                            allowedClusterName = config.allowedClusterName,
                            allowedSubjects = config.allowedSubjects.toSet().ifEmpty { null },
                        )
                    }.also {
                        log.info("loaded ${it.size} external auth providers from AUTH_PROVIDER_CONFIGS: {}", configs)
                    }
            }
            wellknownUrl != null -> {
                log.info("using single external auth provider from AUTH_WELL_KNOWN_URL={} (legacy)", wellknownUrl)
                listOf(AuthProvider.fromWellKnown(wellknownUrl))
            }
            else -> {
                val selfSignedIssuer = konfig[Key(AUTH_CLIENT_ID, stringType)]
                log.info("using self-signed auth provider with issuer=$selfSignedIssuer")
                listOf(AuthProvider.fromSelfSigned(selfSignedIssuer, jwks))
            }
        }

    return ClientRegistrationAuthProperties(
        authProviders = providers,
        acceptedAudience = konfig[Key(AUTH_ACCEPTED_AUDIENCE, listType(stringType, Regex(",")))],
        softwareStatementJwks = jwks,
    )
}

fun federatedClientAuthProperties(): FederatedClientAuthProperties {
    val wellKnownUrls =
        konfig
            .getOrNull(Key(FEDERATED_CLIENT_AUTH_ISSUERS, stringType))
            ?.split(",")
            ?.map { it.trim() }
            ?.filter { it.isNotEmpty() }
            ?: emptyList()

    if (wellKnownUrls.isEmpty()) {
        log.info("federated client authentication disabled (no $FEDERATED_CLIENT_AUTH_ISSUERS configured)")
        return FederatedClientAuthProperties()
    }

    val issuers =
        wellKnownUrls
            .map { FederatedIssuer.fromWellKnown(it) }
            .associateBy { it.issuer }
    log.info("loaded ${issuers.size} federated client auth issuers: ${issuers.keys}")

    return FederatedClientAuthProperties(
        allowedIssuers = issuers,
        audience = konfig.getOrNull(Key(FEDERATED_CLIENT_AUTH_AUDIENCE, stringType)),
        maxAssertionLifetimeSeconds =
            konfig.getOrElse(
                Key(FEDERATED_CLIENT_AUTH_MAX_LIFETIME_SECONDS, longType),
                FederatedClientAuthProperties.DEFAULT_MAX_LIFETIME_SECONDS,
            ),
    )
}
