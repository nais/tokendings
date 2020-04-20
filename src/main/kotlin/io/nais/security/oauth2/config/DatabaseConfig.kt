package io.nais.security.oauth2.config

import com.zaxxer.hikari.HikariConfig
import com.zaxxer.hikari.HikariDataSource
import org.flywaydb.core.Flyway

object InmemoryDatabaseConfig {
    val instance = DatabaseConfig(
        "jdbc:h2:mem:test",
        "user",
        "pwd"
    )
}

data class DatabaseConfig(
    val url: String,
    val user: String,
    val password: String
)

fun dataSourceFrom(databaseConfig: DatabaseConfig): HikariDataSource {
    return HikariDataSource(hikariConfig(databaseConfig))
}

internal fun migrate(dataSource: HikariDataSource, initSql: String = ""): Int =
    Flyway.configure().dataSource(dataSource).initSql(initSql).load().migrate()

internal fun clean(dataSource: HikariDataSource) = Flyway.configure().dataSource(dataSource).load().clean()

private fun hikariConfig(databaseConfig: DatabaseConfig) =
    HikariConfig().apply {
        jdbcUrl = databaseConfig.url
        maximumPoolSize = 3
        minimumIdle = 1
        idleTimeout = 10001
        connectionTimeout = 1000
        maxLifetime = 30001
        username = databaseConfig.user
        password = databaseConfig.password
    }
