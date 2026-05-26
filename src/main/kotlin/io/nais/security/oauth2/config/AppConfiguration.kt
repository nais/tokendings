package io.nais.security.oauth2.config

import com.auth0.jwk.Jwk
import com.auth0.jwk.JwkException
import com.auth0.jwk.JwkProvider
import com.auth0.jwk.JwkProviderBuilder
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.nimbusds.jose.jwk.JWKSet
import com.zaxxer.hikari.HikariDataSource
import io.ktor.client.call.body
import io.ktor.client.request.get
import io.nais.security.oauth2.config.JwkCache.BUCKET_SIZE
import io.nais.security.oauth2.config.JwkCache.CACHE_SIZE
import io.nais.security.oauth2.config.JwkCache.EXPIRES_IN
import io.nais.security.oauth2.health.DatabaseHealthCheck
import io.nais.security.oauth2.health.HealthCheck
import io.nais.security.oauth2.keystore.RotatingKeyStore
import io.nais.security.oauth2.keystore.RotatingKeyStorePostgres
import io.nais.security.oauth2.model.CacheProperties
import io.nais.security.oauth2.model.ClaimMappings
import io.nais.security.oauth2.model.SubjectTokenIssuerMetadata
import io.nais.security.oauth2.model.WellKnownForBearerAuth
import io.nais.security.oauth2.registration.ClientRegistry
import io.nais.security.oauth2.registration.ClientRegistryPostgres
import io.nais.security.oauth2.retryingHttpClient
import io.nais.security.oauth2.token.TokenIssuer
import kotlinx.coroutines.runBlocking
import mu.KotlinLogging
import java.net.URI
import java.time.Duration
import java.util.concurrent.TimeUnit
import javax.sql.DataSource
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.seconds

private val log = KotlinLogging.logger {}

object JwkCache {
    const val CACHE_SIZE = 10L
    const val EXPIRES_IN = 24L
    const val BUCKET_SIZE = 10L
}

data class AppConfiguration(
    val serverProperties: ServerProperties,
    val clientRegistry: ClientRegistry,
    val authorizationServerProperties: AuthorizationServerProperties,
    val clientRegistrationAuthProperties: ClientRegistrationAuthProperties,
    val databaseHealthCheck: HealthCheck,
) {
    val tokenIssuer: TokenIssuer = TokenIssuer(authorizationServerProperties)
}

data class ServerProperties(
    val port: Int,
)

data class ClientRegistryProperties(
    val dataSource: DataSource,
)

data class ClientRegistrationAuthProperties(
    val authProviders: List<AuthProvider>,
    val acceptedAudience: List<String>,
    val softwareStatementJwks: JWKSet,
) {
    init {
        val issuers = authProviders.map { it.issuer }
        require(issuers.size == issuers.distinct().size) {
            "Duplicate issuers in auth providers: ${issuers.groupingBy { it }.eachCount().filter { it.value > 1 }.keys}"
        }
    }

    val providersByIssuer: Map<String, AuthProvider> = authProviders.associateBy { it.issuer }
}

class AuthProvider(
    val issuer: String,
    val jwkProvider: JwkProvider,
    val allowedClusterName: String? = null,
    val allowedSubjects: Set<String>? = null,
) {
    companion object {
        fun fromWellKnown(
            wellKnownUrl: String,
            allowedClusterName: String? = null,
            allowedSubjects: Set<String>? = null,
        ): AuthProvider {
            val wellKnown: WellKnownForBearerAuth =
                runBlocking {
                    log.info("getting external auth provider discovery document from well-known url=$wellKnownUrl")
                    retryingHttpClient.get(wellKnownUrl).body()
                }
            val jwk =
                JwkProviderBuilder(URI(wellKnown.jwksUri).toURL())
                    .cached(CACHE_SIZE, EXPIRES_IN, TimeUnit.HOURS)
                    .rateLimited(BUCKET_SIZE, 1, TimeUnit.MINUTES)
                    .headers(mapOf("Accept" to "application/json, application/jwk-set+json"))
                    .build()
            return AuthProvider(wellKnown.issuer, jwk, allowedClusterName, allowedSubjects)
        }

        fun fromSelfSigned(
            issuer: String,
            jwkSet: JWKSet,
        ): AuthProvider {
            val jwk =
                JwkProvider { keyId ->
                    Jwk.fromValues(jwkSet.getKeyByKeyId(keyId)?.toJSONObject() ?: throw JwkException("JWK not found"))
                }
            jwkSet.keys.forEach { key ->
                log.info("validate key with kid=${key.keyID} from JWKS")
                jwk.get(key.keyID).publicKey
            }
            return AuthProvider(issuer, jwk)
        }
    }
}

class AuthorizationServerProperties(
    val issuerUrl: String,
    val subjectTokenIssuers: List<SubjectTokenIssuer>,
    val tokenExpiry: Long = 300,
    val rotatingKeyStore: RotatingKeyStore,
    val clientAssertionMaxExpiry: Long = 120,
) {
    fun tokenEndpointUrl() = issuerUrl.path(TOKEN_PATH)

    fun clientRegistrationUrl() = issuerUrl.path(REGISTRATION_PATH)

    companion object {
        const val WELL_KNOWN_PATH = "/.well-known/oauth-authorization-server"
        const val AUTHORIZATION_PATH = "/authorization"
        const val TOKEN_PATH = "/token"
        const val JWKS_PATH = "/jwks"
        const val REGISTRATION_PATH = "/registration/client"
    }
}

class SubjectTokenIssuer(
    private val wellKnownUrl: String,
    val subjectTokenClaimMappings: ClaimMappings = emptyMap(),
) {
    val wellKnown: SubjectTokenIssuerMetadata =
        runBlocking {
            log.info("getting subject token discovery document from well-known url=$wellKnownUrl")
            retryingHttpClient.get(wellKnownUrl).body()
        }
    val issuer = wellKnown.issuer
    val cacheProperties =
        CacheProperties(
            timeToLive = 6.hours,
            jwksURL = URI(wellKnown.jwksUri).toURL(),
            connectionTimeout = 5.seconds,
            readTimeout = 5.seconds,
            refreshAheadTime = 1.hours,
        )

    init {
        if (subjectTokenClaimMappings.isNotEmpty()) {
            val mappings = jacksonObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(subjectTokenClaimMappings)
            log.info("loaded subject token claim mappings for issuer=$issuer: $mappings}")
        }
    }
}

data class KeyStoreProperties(
    val dataSource: DataSource,
    val rotationInterval: Duration,
)

fun String.path(path: String) = "${this.removeSuffix("/")}/${path.removePrefix("/")}"

fun rotatingKeyStore(
    dataSource: DataSource,
    rotationInterval: Duration = Duration.ofDays(1),
): RotatingKeyStorePostgres =
    RotatingKeyStorePostgres(
        KeyStoreProperties(
            dataSource = dataSource,
            rotationInterval = rotationInterval,
        ),
    )

internal fun clientRegistry(dataSource: HikariDataSource): ClientRegistryPostgres =
    ClientRegistryPostgres(
        ClientRegistryProperties(
            dataSource,
        ),
    )

internal fun migrate(databaseConfig: DatabaseConfig) =
    dataSourceFrom(databaseConfig).apply {
        migrate(this)
    }

internal fun databaseHealthCheck(dataSource: HikariDataSource) = DatabaseHealthCheck(dataSource)
