package io.nais.security.oauth2.config

import com.codahale.metrics.MetricRegistry
import com.zaxxer.hikari.HikariConfig
import com.zaxxer.hikari.HikariDataSource
import io.nais.security.oauth2.config.HikariProperties.CONNECTION_TIMEOUT_NON_PROD
import io.nais.security.oauth2.config.HikariProperties.CONNECTION_TIMEOUT_PROD
import io.nais.security.oauth2.config.HikariProperties.IDLE_TIMEOUT_NON_PROD
import io.nais.security.oauth2.config.HikariProperties.IDLE_TIMEOUT_PROD
import io.nais.security.oauth2.config.HikariProperties.MAX_LIFETIME_NON_PROD
import io.nais.security.oauth2.config.HikariProperties.MAX_LIFETIME_PROD
import io.nais.security.oauth2.config.HikariProperties.MAX_POOL_SIZE_NON_PROD
import io.nais.security.oauth2.config.HikariProperties.MAX_POOL_SIZE_PROD
import io.nais.security.oauth2.config.HikariProperties.MIN_IDLE_CONNECTIONS_NON_PROD
import io.nais.security.oauth2.config.HikariProperties.MIN_IDLE_CONNECTIONS_PROD
import io.prometheus.client.CollectorRegistry
import io.prometheus.client.dropwizard.DropwizardExports
import org.flywaydb.core.Flyway
import org.flywaydb.core.api.output.MigrateResult

data class DatabaseConfig(
    val url: String,
    val metricRegistry: MetricRegistry,
)

fun dataSourceFrom(databaseConfig: DatabaseConfig): HikariDataSource {
    return HikariDataSource(hikariConfig(databaseConfig))
}

internal fun migrate(dataSource: HikariDataSource, initSql: String = ""): MigrateResult? =
    Flyway.configure().dataSource(dataSource).initSql(initSql).load().migrate()

internal fun clean(dataSource: HikariDataSource) =
    Flyway.configure().cleanDisabled(false).dataSource(dataSource).load().clean()

private fun hikariConfig(databaseConfig: DatabaseConfig) =
    HikariConfig().apply {
        jdbcUrl = databaseConfig.url
        if (isNonProd()) {
            maximumPoolSize = MAX_POOL_SIZE_NON_PROD
            minimumIdle = MIN_IDLE_CONNECTIONS_NON_PROD
            idleTimeout = IDLE_TIMEOUT_NON_PROD
            connectionTimeout = CONNECTION_TIMEOUT_NON_PROD
            maxLifetime = MAX_LIFETIME_NON_PROD
        } else {
            maximumPoolSize = MAX_POOL_SIZE_PROD
            minimumIdle = MIN_IDLE_CONNECTIONS_PROD
            idleTimeout = IDLE_TIMEOUT_PROD
            connectionTimeout = CONNECTION_TIMEOUT_PROD
            maxLifetime = MAX_LIFETIME_PROD
        }
        initializationFailTimeout = HikariProperties.INITIALIZATION_FAIL_TIMEOUT
        metricRegistry = databaseConfig.metricRegistry
    }.also {
        CollectorRegistry.defaultRegistry.register(DropwizardExports(databaseConfig.metricRegistry))
    }

object HikariProperties {
    // Production-specific
    const val IDLE_TIMEOUT_PROD = 300000L
    const val CONNECTION_TIMEOUT_PROD = 5000L
    const val MAX_LIFETIME_PROD = 1800000L
    const val MAX_POOL_SIZE_PROD = 10
    const val MIN_IDLE_CONNECTIONS_PROD = 5

    // Non-production-specific
    const val IDLE_TIMEOUT_NON_PROD = 600000L
    const val CONNECTION_TIMEOUT_NON_PROD = 10000L
    const val MAX_LIFETIME_NON_PROD = 3600000L
    const val MAX_POOL_SIZE_NON_PROD = 10
    const val MIN_IDLE_CONNECTIONS_NON_PROD = 5

    // Common configuration
    const val INITIALIZATION_FAIL_TIMEOUT = 10000L
}
