package io.nais.security.oauth2.keystore

import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.nais.security.oauth2.config.RsaKeyStoreProperties
import io.nais.security.oauth2.mock.DataSource
import io.nais.security.oauth2.mock.withMigratedDb
import org.awaitility.Awaitility
import org.junit.Before
import org.junit.jupiter.api.Test
import java.time.LocalDateTime
import java.util.concurrent.TimeUnit

class RsaKeyStoreTest {

    @Before
    fun setup() {
        Awaitility.reset()
    }

    @Test
    fun `keyStore should insert new record when databse is empty`() {
        withMigratedDb {
            with(RsaKeyStore(RsaKeyStoreProperties(DataSource.instance, 2))) {
                val createdRsaKeys = initKeyStorage()
                val readKeys = read()
                readKeys shouldNotBe null
                createdRsaKeys.currentKey shouldBe readKeys.currentKey
                createdRsaKeys.previousKey shouldBe readKeys.previousKey
                createdRsaKeys.nextKey shouldBe readKeys.nextKey
            }
        }
    }

    @Test
    fun `keystore should add new initial record on empty database or update existing record on expired keys`() {
        withMigratedDb {
            with(RsaKeyStore(RsaKeyStoreProperties(DataSource.instance, 1))) {

                val rsaKeysInitial = activeKeys()
                val now = LocalDateTime.now()
                rsaKeysInitial.expired(now) shouldBe false
                rsaKeysInitial.expired(now.plusSeconds(2)) shouldBe true

                Awaitility
                    .with().pollDelay(1, TimeUnit.SECONDS)
                    .then().await().atMost(2, TimeUnit.SECONDS)
                    .until {
                        val rsaKeysRotated = activeKeys()
                        rsaKeysRotated.expired(LocalDateTime.now()) shouldBe false
                        rsaKeysInitial.nextKey shouldBe rsaKeysRotated.currentKey
                        rsaKeysInitial.currentKey shouldBe rsaKeysRotated.previousKey
                        rsaKeysInitial.currentKey.toRSAKey()?.isPrivate shouldBe true
                        rsaKeysInitial.nextKey.toRSAKey()?.isPrivate shouldBe true
                        rsaKeysInitial.previousKey.toRSAKey()?.isPrivate == true
                    }
            }
        }
    }
}
