package io.nais.security.oauth2.registration

import io.nais.security.oauth2.model.ClientId
import io.nais.security.oauth2.model.OAuth2Client
import io.nais.security.oauth2.utils.withTimer
import kotliquery.Query
import kotliquery.Row
import kotliquery.queryOf
import kotliquery.sessionOf
import kotliquery.using
import org.postgresql.util.PGobject
import javax.sql.DataSource

class ClientStore(
    private val dataSource: DataSource,
) {
    companion object {
        private const val TABLE_NAME = "clients"
    }

    fun storeClient(oAuth2Client: OAuth2Client): Int =
        withTimer("storeClient") {
            using(sessionOf(dataSource)) { session ->
                session.run(upsertQuery(oAuth2Client).asUpdate)
            }
        }

    private fun upsertQuery(oAuth2Client: OAuth2Client): Query =
        queryOf(
            """
        INSERT INTO $TABLE_NAME(client_id, data) values (:client_id, :data)
        ON CONFLICT (client_id) 
            DO UPDATE SET 
            data = EXCLUDED.data
        WHERE clients.data IS DISTINCT FROM EXCLUDED.data;
            """.trimMargin(),
            mapOf(
                "client_id" to oAuth2Client.clientId,
                "data" to
                    PGobject().also {
                        it.type = "jsonb"
                        it.value = oAuth2Client.toJson()
                    },
            ),
        )

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
                    queryOf("""SELECT data FROM $TABLE_NAME WHERE client_id=?""", clientId)
                        .map {
                            it.mapToOAuth2Client()
                        }.asSingle,
                )
            }
        }

    fun findClients(clientIds: List<String>): Map<String, OAuth2Client> =
        withTimer("findClients") {
            if (clientIds.isEmpty()) return emptyMap()
            val placeholders = clientIds.joinToString(",") { "?" }
            using(sessionOf(dataSource)) { session ->
                session
                    .run(
                        queryOf("""SELECT data FROM $TABLE_NAME WHERE client_id IN ($placeholders)""", *clientIds.toTypedArray())
                            .map { it.mapToOAuth2Client() }
                            .asList,
                    ).associateBy { it.clientId }
            }
        }

    fun findAll(): List<OAuth2Client> =
        withTimer("findAll") {
            using(sessionOf(dataSource)) { session ->
                session.run(
                    queryOf("""SELECT * FROM $TABLE_NAME""")
                        .map {
                            it.mapToOAuth2Client()
                        }.asList,
                )
            }
        }

    private fun Row.mapToOAuth2Client(): OAuth2Client = OAuth2Client.fromJson(this.string("data"))
}
