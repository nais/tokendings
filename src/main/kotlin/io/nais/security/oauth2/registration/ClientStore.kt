package io.nais.security.oauth2.registration

import io.nais.security.oauth2.model.ClientId
import io.nais.security.oauth2.model.OAuth2Client
import io.nais.security.oauth2.metrics.Metrics
import kotliquery.Query
import kotliquery.Row
import kotliquery.queryOf
import kotliquery.sessionOf
import kotliquery.using
import org.postgresql.util.PGobject
import javax.sql.DataSource

class ClientStore(private val dataSource: DataSource) {

    companion object {
        private const val TABLE_NAME = "clients"
        private const val PRIMARY_KEY = "client_id"
    }

    fun storeClient(oAuth2Client: OAuth2Client): Int =
        withTimer("storeClient") {
            using(sessionOf(dataSource)) { session ->
                session.run(upsertQuery(oAuth2Client).asUpdate)
            }
        }

    private fun upsertQuery(oAuth2Client: OAuth2Client): Query {
        return queryOf(
            """
            INSERT INTO $TABLE_NAME(client_id, data) values (:client_id, :data)
            ON CONFLICT (client_id)
                DO UPDATE SET
                data=:data;
            """.trimMargin(),
            mapOf(
                "client_id" to oAuth2Client.clientId,
                "data" to PGobject().also {
                    it.type = "jsonb"
                    it.value = oAuth2Client.toJson()
                }
            )
        )
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
            """UPDATE $TABLE_NAME SET $keyValues WHERE client_id=:client_id""".trimMargin(), columnMap
        )
    }

    fun delete(clientId: ClientId) =
        withTimer("delete") {
            using(sessionOf(dataSource)) { session ->
                session.run(queryOf("""DELETE FROM $TABLE_NAME WHERE client_id=?""", clientId).asUpdate)
            }
        }

    fun find(clientId: ClientId): OAuth2Client? =
        withTimer("find") {
            using(sessionOf(dataSource)) { session ->
                session.run(
                    queryOf("""SELECT * FROM $TABLE_NAME WHERE client_id=?""", clientId)
                        .map {
                            it.mapToOAuth2Client()
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
                            it.mapToOAuth2Client()
                        }.asList
                )
            }
        }

    private fun Row.mapToOAuth2Client(): OAuth2Client {
        return OAuth2Client.fromJson(this.string("data"))
    }

    private fun OAuth2Client.mapToColumns(): Map<String, *> =
        mapOf(
            "client_id" to this.clientId,
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
