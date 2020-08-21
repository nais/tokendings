package io.nais.security.oauth2.rsakeystore

import io.nais.security.oauth2.token.toJSON
import io.nais.security.oauth2.token.toRSAKey
import io.nais.security.oauth2.utils.generateRsaKey
import kotliquery.Query
import kotliquery.Row
import kotliquery.queryOf
import kotliquery.sessionOf
import kotliquery.using
import mu.KotlinLogging
import org.slf4j.Logger
import java.time.LocalDateTime
import javax.sql.DataSource

private val log: Logger = KotlinLogging.logger { }

class KeyStore(
    private val dataSource: DataSource
) {

    // Could be an ENV?
    var TTL = 24 * 60 * 60.toLong()

    companion object {
        private const val TABLE_NAME = "rsakeys"
        const val ID = 1L
    }

    fun keys(): RSAKeys {
        val rsaKeys = read()
        if (rsaKeys.expired(LocalDateTime.now())) {
            val newKey = generateRsaKey()
            val expiry = LocalDateTime.now().plusSeconds(TTL)
            save(rsaKeys.rotate(newKey, expiry))
            log.info("RSA KEY rotated, next expiry: $expiry")
        }
        log.debug("RSA KEY fetched from cache")
        return rsaKeys
    }

    fun read() = using(sessionOf(dataSource)) { session ->
        session.run(
            queryOf("""SELECT * FROM $TABLE_NAME""")
                .map {
                    it.mapToRsaKeys()
                }.asSingle
        )
        // Only if database is empty..
    } ?: initKeyStorage()

    private fun Row.mapToRsaKeys(): RSAKeys {
        return RSAKeys(
            currentKey = this.string("current_key").toRSAKey(),
            previousKey = this.string("previous_key").toRSAKey(),
            nextKey = this.string("next_key").toRSAKey(),
            expiry = this.localDateTime("expiry")
        ).toKey()
    }

    fun initKeyStorage() = initRSAKeys().apply {
        save(this)
        log.info("RSA KEY initialised, next expiry: ${this.expiry}")
        return this
    }

    private fun initRSAKeys() = RSAKeys(
        currentKey = generateRsaKey(),
        previousKey = generateRsaKey(),
        nextKey = generateRsaKey(),
        expiry = LocalDateTime.now().plusSeconds(TTL)
    )

    private fun save(rsaKeys: RSAKeys) =
        using(sessionOf(dataSource)) { session ->
            session.run(
                modify(
                    rsaKeys
                ).asUpdate
            )
        }

    private fun modify(rsaKeys: RSAKeys): Query {
        return queryOf(
            """
            INSERT INTO $TABLE_NAME(id, current_key, previous_key, next_key, expiry) VALUES (:id, :current_key, :previous_key, :next_key, :expiry)
            ON CONFLICT (id)
                DO UPDATE SET
                current_key=:current_key, previous_key=:previous_key, next_key=:next_key, expiry=:expiry;
            """.trimMargin(),
            mapOf(
                "id" to ID,
                "current_key" to rsaKeys.currentKey.toJSON(),
                "previous_key" to rsaKeys.previousKey.toJSON(),
                "next_key" to rsaKeys.nextKey.toJSON(),
                "expiry" to rsaKeys.expiry
            )
        )
    }
}
