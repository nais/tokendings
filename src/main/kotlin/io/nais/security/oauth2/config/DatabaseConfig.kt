package io.nais.security.oauth2.config

import com.zaxxer.hikari.HikariConfig
import com.zaxxer.hikari.HikariDataSource
import io.nais.security.oauth2.config.HikariProperties.CONNECTION_TIMEOUT
import io.nais.security.oauth2.config.HikariProperties.IDLE_TIMEOUT
import io.nais.security.oauth2.config.HikariProperties.INITIALIZATION_FAIL_TIMEOUT
import io.nais.security.oauth2.config.HikariProperties.MAX_LIFETIME
import io.nais.security.oauth2.config.HikariProperties.MAX_POOL_SIZE
import io.nais.security.oauth2.config.HikariProperties.MIN_IDLE_CONNECTIONS
import org.flywaydb.core.Flyway
import org.flywaydb.core.api.output.MigrateResult

data class DatabaseConfig(
    val url: String,
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
        maximumPoolSize = MAX_POOL_SIZE
        minimumIdle = MIN_IDLE_CONNECTIONS
        idleTimeout = IDLE_TIMEOUT
        connectionTimeout = CONNECTION_TIMEOUT
        maxLifetime = MAX_LIFETIME
        initializationFailTimeout = INITIALIZATION_FAIL_TIMEOUT
    }

object HikariProperties {
    const val IDLE_TIMEOUT = 10001L
    const val CONNECTION_TIMEOUT = 3000L
    const val MAX_LIFETIME = 30001L
    const val MAX_POOL_SIZE = 10
    const val MIN_IDLE_CONNECTIONS = 5
    const val INITIALIZATION_FAIL_TIMEOUT = 10000L
}
