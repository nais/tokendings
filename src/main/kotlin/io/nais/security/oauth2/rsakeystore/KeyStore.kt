package io.nais.security.oauth2.rsakeystore

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

    companion object {
        private const val TABLE_NAME = "rsakeys"
        var DEFAULT_KEY_ROTATION = 24 * 60 * 60.toLong()
        const val ID = 1L
    }

    val keys: RSAKeys
        get() {
            val rsaKeys = read()
            rsaKeys?.let {
                if (rsaKeys.expired(LocalDateTime.now())) {
                    val newKey = generateRsaKey()
                    val expiry = LocalDateTime.now().plusSeconds(DEFAULT_KEY_ROTATION)
                    save(rsaKeys.rotate(newKey, expiry))
                    log.info("RSA KEY rotated, next expiry: $expiry")
                }
                log.debug("RSA KEY fetched from cache")
                return rsaKeys
            }
            return initKeys()
        }

    fun read() = using(sessionOf(dataSource)) { session ->
        session.run(
            queryOf("""SELECT * FROM $TABLE_NAME""")
                .map {
                    it.mapToRsaKeys()
                }.asSingle
        )
    }

    private fun Row.mapToRsaKeys(): RSAKeys {
        return RSAKeys(
            currentKey = this.string("current_key").toRSAKey(),
            previousKey = this.string("previous_key").toRSAKey(),
            nextKey = this.string("next_key").toRSAKey(),
            expiry = this.localDateTime("expiry")
        ).toKey()
    }

    fun initKeys() = RSAKeys().initKeys(DEFAULT_KEY_ROTATION).apply {
        save(this)
        log.info("RSA KEY initialised, next expiry: ${this.expiry!!}")
        return this
    }

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
                "current_key" to rsaKeys.currentKey?.toJSONString(),
                "previous_key" to rsaKeys.previousKey?.toJSONString(),
                "next_key" to rsaKeys.nextKey?.toJSONString(),
                "expiry" to rsaKeys.expiry
            )
        )
    }

    // TODO Better solution, only used for testing
    fun setExpires(seconds: Long) {
        DEFAULT_KEY_ROTATION = seconds
    }
}
