package io.nais.security.oauth2.mock

import com.auth0.jwk.JwkProvider
import com.zaxxer.hikari.HikariDataSource
import io.ktor.application.Application
import io.ktor.util.KtorExperimentalAPI
import io.mockk.every
import io.mockk.mockk
import io.nais.security.oauth2.authentication.BearerTokenAuth
import io.nais.security.oauth2.config.AppConfiguration
import io.nais.security.oauth2.config.AuthorizationServerProperties
import io.nais.security.oauth2.config.ClientRegistrationAuthProperties
import io.nais.security.oauth2.config.ClientRegistryProperties
import io.nais.security.oauth2.config.ServerProperties
import io.nais.security.oauth2.config.SubjectTokenIssuer
import io.nais.security.oauth2.config.clean
import io.nais.security.oauth2.config.migrate
import io.nais.security.oauth2.config.rotatingKeyStore
import io.nais.security.oauth2.keystore.RotatingKeyStore
import io.nais.security.oauth2.model.AccessPolicy
import io.nais.security.oauth2.model.ClientId
import io.nais.security.oauth2.model.JsonWebKeys
import io.nais.security.oauth2.model.OAuth2Client
import io.nais.security.oauth2.model.WellKnown
import io.nais.security.oauth2.registration.ClientRegistry
import io.nais.security.oauth2.routing.DefaultRouting
import io.nais.security.oauth2.tokenExchangeApp
import io.nais.security.oauth2.utils.jwkSet
import no.nav.security.mock.oauth2.MockOAuth2Server
import org.testcontainers.containers.PostgreSQLContainer
import java.time.Duration

@KtorExperimentalAPI
fun mockConfig(
    mockOAuth2Server: MockOAuth2Server? = null,
    clientRegistrationAuthProperties: ClientRegistrationAuthProperties? = null
): AppConfiguration {

    val issuerUrl = "http://localhost:8080"
    val authorizationServerProperties = AuthorizationServerProperties(
        issuerUrl = issuerUrl,
        subjectTokenIssuers = mockOAuth2Server?.let {
            listOf(SubjectTokenIssuer(it.wellKnownUrl("mock1").toString()))
        } ?: emptyList(),
        rotatingKeyStore = rotatingKeyStore()
    )
    val clientRegAuthProperties = when {
        clientRegistrationAuthProperties != null -> clientRegistrationAuthProperties
        mockOAuth2Server != null -> ClientRegistrationAuthProperties(
            identityProviderWellKnownUrl = mockOAuth2Server.wellKnownUrl("aadmock").toString(),
            acceptedAudience = listOf("tokendings"),
            acceptedRoles = BearerTokenAuth.ACCEPTED_ROLES_CLAIM_VALUE,
            softwareStatementJwks = jwkSet()
        )
        else -> mockBearerTokenAuthenticationProperties()
    }

    val clientRegistry = MockClientRegistry()
    return AppConfiguration(
        ServerProperties(8080),
        clientRegistry,
        authorizationServerProperties,
        clientRegAuthProperties
    )
}

@KtorExperimentalAPI
fun mockBearerTokenAuthenticationProperties(): ClientRegistrationAuthProperties =
    mockBearerTokenAuthenticationProperties(
        mockk<WellKnown>().also {
            every { it.jwksUri } returns "http://na"
            every { it.issuer } returns "http://na"
        },
        mockk()
    )

@KtorExperimentalAPI
fun mockBearerTokenAuthenticationProperties(wellKnown: WellKnown, jwkProvider: JwkProvider): ClientRegistrationAuthProperties =
    mockk<ClientRegistrationAuthProperties>().also {
        every { it.wellKnown } returns wellKnown
        every { it.jwkProvider } returns jwkProvider
    }

fun rotatingKeyStore(): RotatingKeyStore = rotatingKeyStore(DataSource.instance)

fun rotatingKeyStore(rotationInterval: Duration): RotatingKeyStore = rotatingKeyStore(DataSource.instance, rotationInterval)

@KtorExperimentalAPI
fun MockApp(
    config: AppConfiguration = mockConfig()
): Application.() -> Unit {
    return fun Application.() {
        tokenExchangeApp(config, DefaultRouting(config))
    }
}

class MockClientRegistry : ClientRegistry(
    ClientRegistryProperties(DataSource.instance.apply { clean(this) }.apply { migrate(this) })
) {

    private fun registerClientAndGenerateKeys(
        clientId: String,
        accessPolicy: AccessPolicy = AccessPolicy(),
        allowedScopes: List<String> = emptyList(),
        allowedGrantTypes: List<String> = emptyList()
    ): OAuth2Client =
        registerClient(
            OAuth2Client(
                clientId,
                JsonWebKeys(jwkSet()),
                accessPolicy,
                accessPolicy,
                allowedScopes,
                allowedGrantTypes
            )
        )

    fun register(clientId: ClientId, accessPolicy: AccessPolicy = AccessPolicy()): OAuth2Client = this.registerClientAndGenerateKeys(clientId, accessPolicy)
}

fun <R> withMockOAuth2Server(
    test: MockOAuth2Server.() -> R
): R {
    val server = MockOAuth2Server()
    server.start()
    try {
        return server.test()
    } finally {
        server.shutdown()
    }
}

internal object PostgresContainer {
    val instance by lazy {
        PostgreSQLContainer<Nothing>("postgres:11.2").apply {
            start()
        }
    }
}

internal object DataSource {
    val instance: HikariDataSource by lazy {
        HikariDataSource().apply {
            username = PostgresContainer.instance.username
            password = PostgresContainer.instance.password
            jdbcUrl = PostgresContainer.instance.jdbcUrl
            connectionTimeout = 1000L
        }
    }
}

internal fun withCleanDb(test: () -> Unit) = DataSource.instance.also { clean(it) }.run { test() }

internal fun withMigratedDb(test: () -> Unit) =
    DataSource.instance.also { clean(it) }.also { migrate(it) }.run { test() }
