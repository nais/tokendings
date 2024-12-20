package io.nais.security.oauth2.keystore

import io.nais.security.oauth2.token.toJSON
import io.nais.security.oauth2.token.toRSAKey
import io.nais.security.oauth2.utils.withTimer
import io.opentelemetry.instrumentation.annotations.WithSpan
import kotliquery.Query
import kotliquery.Row
import kotliquery.queryOf
import kotliquery.sessionOf
import kotliquery.using
import java.time.LocalDateTime
import javax.sql.DataSource

class KeyStore(
    private val dataSource: DataSource,
) {
    companion object {
        private const val TABLE_NAME = "rotatable_keys"
        const val ID = 1L
    }

    @WithSpan
    fun read(): RotatableKeys? =
        withTimer("readKeys") {
            using(sessionOf(dataSource)) { session ->
                session.run(
                    queryOf("""SELECT * FROM $TABLE_NAME""")
                        .map {
                            it.mapToRsaKeys()
                        }.asSingle,
                )
            }
        }

    fun save(rotatableKeys: RotatableKeys) =
        using(sessionOf(dataSource)) { session ->
            session.run(queryOf("""SET TRANSACTION ISOLATION LEVEL REPEATABLE READ""").asExecute)
            session.transaction { tx ->
                tx.run(modify(rotatableKeys).asUpdate)
            }
        }

    private fun Row.mapToRsaKeys(): RotatableKeys =
        RotatableKeys(
            currentKey = this.string("current_key").toRSAKey(),
            previousKey = this.string("previous_key").toRSAKey(),
            nextKey = this.string("next_key").toRSAKey(),
            expiry = LocalDateTime.parse(this.string("expiry")),
        )

    private fun modify(rotatableKeys: RotatableKeys): Query =
        queryOf(
            """
            INSERT INTO $TABLE_NAME(id, current_key, previous_key, next_key, expiry) VALUES 
            (:id, :current_key, :previous_key, :next_key, :expiry)
            ON CONFLICT (id)
                DO UPDATE SET
                current_key=:current_key, previous_key=:previous_key, next_key=:next_key, expiry=:expiry;
            """.trimMargin(),
            mapOf(
                "id" to ID,
                "current_key" to rotatableKeys.currentKey.toJSON(),
                "previous_key" to rotatableKeys.previousKey.toJSON(),
                "next_key" to rotatableKeys.nextKey.toJSON(),
                "expiry" to rotatableKeys.expiry.toString(),
            ),
        )
}
