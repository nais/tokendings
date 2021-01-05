package io.nais.security.oauth2.health

import kotliquery.queryOf
import kotliquery.sessionOf
import kotliquery.using
import javax.sql.DataSource

interface HealthCheck {
    fun ping(): String
}

class DatabaseHealthCheck(private val dataSource: DataSource) : HealthCheck {
    override fun ping(): String =
        using(sessionOf(dataSource)) { session ->
            session.run(
                queryOf("SELECT now()")
                    .map {
                        "pong"
                    }.asSingle
            ) ?: "pong"
        }
}
