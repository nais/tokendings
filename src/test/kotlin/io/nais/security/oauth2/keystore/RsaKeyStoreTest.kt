package io.nais.security.oauth2.keystore

import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.nais.security.oauth2.config.RsaKeyStoreProperties
import io.nais.security.oauth2.mock.DataSource
import io.nais.security.oauth2.mock.withMigratedDb
import org.awaitility.Awaitility
import org.junit.Before
import org.junit.jupiter.api.Test
import java.time.Duration

class RsaKeyStoreTest {

    @Before
    fun setup() {
        Awaitility.reset()
    }

    @Test
    fun `keyStore should insert new record when database is empty`() {
        withMigratedDb {
            with(rsaKeyStore()) {
                val createdRsaKeys = initKeyStorage()
                val readKeys = read()
                readKeys shouldNotBe null
                createdRsaKeys.currentKey shouldBe readKeys.currentKey
                createdRsaKeys.previousKey shouldBe readKeys.previousKey
                createdRsaKeys.nextKey shouldBe readKeys.nextKey
            }
        }
    }

    // TODO: maybe remove rotation interval from RsaKeyStore, only send in DataSource
    private fun rsaKeyStore(): RsaKeyStore = RsaKeyStore(
        RsaKeyStoreProperties(
            DataSource.instance,
            Duration.ofDays(1)
        )
    )
}
