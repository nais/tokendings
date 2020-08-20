package io.nais.security.oauth2.rsakeystore

import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.nais.security.oauth2.mock.DataSource
import io.nais.security.oauth2.mock.withMigratedDb
import org.junit.jupiter.api.Test
import java.lang.Thread.sleep
import java.time.LocalDateTime

class KeyStoreTest {

    @Test
    fun `keyStore should insert new record when db is empty`() {
        withMigratedDb {
            with(KeyStore(DataSource.instance)) {
                val createdRsaKeys = initKeys()
                val readKeys = read()
                readKeys shouldNotBe null
                createdRsaKeys.currentKey shouldBe readKeys?.currentKey
                createdRsaKeys.previousKey shouldBe readKeys?.previousKey
                createdRsaKeys.nextKey shouldBe readKeys?.nextKey
            }
        }
    }

    @Test
    fun `keystore should add new initial record on empty db or update existing record on expired keys`() {
        withMigratedDb {
            with(KeyStore(DataSource.instance)) {
                setExpires(1)
                val rsaKeysInitial = keys
                rsaKeysInitial.expired(LocalDateTime.now()) shouldBe false
                // Go past expiry date
                sleepy(2)
                rsaKeysInitial.expired(LocalDateTime.now()) shouldBe true
                val rsaKeysRotated = keys
                rsaKeysRotated.expired(LocalDateTime.now()) shouldBe false
                rsaKeysInitial.nextKey shouldBe rsaKeysRotated.currentKey
                rsaKeysInitial.currentKey shouldBe rsaKeysRotated.previousKey
                rsaKeysInitial.currentKey?.toRSAKey()?.isPrivate shouldBe true
                rsaKeysInitial.nextKey?.toRSAKey()?.isPrivate shouldBe true
                rsaKeysInitial.previousKey?.toRSAKey()?.isPrivate shouldBe true
            }
        }
    }
}

internal fun sleepy(seconds: Int) {
    try {
        sleep(seconds * 1000.toLong())
    } catch (e: InterruptedException) {
    }
}
