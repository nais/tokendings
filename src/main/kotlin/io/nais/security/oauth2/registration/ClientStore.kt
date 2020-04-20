package io.nais.security.oauth2.registration

import io.nais.security.oauth2.model.ClientId
import io.nais.security.oauth2.model.OAuth2Client
import io.nais.security.oauth2.observability.Metrics
import kotliquery.Query
import kotliquery.Row
import kotliquery.queryOf
import kotliquery.sessionOf
import kotliquery.using
import org.postgresql.util.PGobject
import javax.sql.DataSource

class ClientStore(private val dataSource: DataSource) {

    companion object {
        private const val TABLE_NAME = "CLIENTS"
        private const val PRIMARY_KEY = "CLIENT_ID"
    }

    fun storeClient(oAuth2Client: OAuth2Client): Int =
        withTimer("storeClient") {
            using(sessionOf(dataSource)) { session ->
                when (val rows = session.run(updateQuery(oAuth2Client).asUpdate)) {
                    0 -> session.run(insertQuery(oAuth2Client).asUpdate)
                    else -> rows
                }
            }
        }

    private fun insertQuery(oAuth2Client: OAuth2Client): Query {
        val columnMap = oAuth2Client.mapToColumns()
        val columnNames = columnMap.keys.joinToString(", ")
        val placeholders = columnMap.keys.joinToString(", ") { ":$it" }
        return queryOf(
            """INSERT INTO $TABLE_NAME($columnNames) values ($placeholders)""".trimMargin(), columnMap
        )
    }

    private fun updateQuery(oAuth2Client: OAuth2Client): Query {
        val columnMap = oAuth2Client.mapToColumns()
        val keyValues = columnMap.keys
            .filter { it == PRIMARY_KEY }
            .map { "$it=:$it" }
            .toList().joinToString(", ")
        return queryOf(
            """UPDATE $TABLE_NAME SET $keyValues WHERE CLIENT_ID=:CLIENT_ID""".trimMargin(), columnMap
        )
    }

    fun delete(clientId: ClientId) =
        withTimer("delete") {
            using(sessionOf(dataSource)) { session ->
                session.run(queryOf("""DELETE FROM $TABLE_NAME WHERE CLIENT_ID=?""", clientId).asUpdate)
            }
        }

    fun find(clientId: ClientId): OAuth2Client? =
        withTimer("find") {
            using(sessionOf(dataSource)) { session ->
                session.run(
                    queryOf("""SELECT * FROM $TABLE_NAME WHERE CLIENT_ID=?""", clientId)
                        .map {
                            mapToOAuth2Client(it)
                        }.asSingle
                )
            }
        }

    fun findAll(): List<OAuth2Client> =
        withTimer("findAll") {
            using(sessionOf(dataSource)) { session ->
                session.run(
                    queryOf("""SELECT * FROM $TABLE_NAME""")
                        .map {
                            mapToOAuth2Client(it)
                        }.asList
                )
            }
        }

    private fun mapToOAuth2Client(row: Row): OAuth2Client {
        return OAuth2Client.fromJson(row.string("data"))
    }

    private fun OAuth2Client.mapToColumns(): Map<String, *> =
        mapOf(
            "CLIENT_ID" to this.clientId,
            "data" to PGobject().also {
                it.type = "jsonb"
                it.value = this.toJson()
            }
        )

    private inline fun <reified R : Any?> withTimer(timerLabel: String, block: () -> R): R {
        val timer = Metrics.dbTimer.labels(timerLabel).startTimer()
        try {
            return block()
        } finally {
            timer.observeDuration()
        }
    }
}
