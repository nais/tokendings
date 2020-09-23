package io.nais.security.oauth2.keystore

import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.nais.security.oauth2.config.RsaKeyStoreProperties
import io.nais.security.oauth2.mock.DataSource
import io.nais.security.oauth2.mock.withMigratedDb
import org.junit.jupiter.api.Test

class RsaKeyStoreTest {

    @Test
    fun `keyStore should insert new record when databse is empty`() {
        withMigratedDb {
            with(RsaKeyStore(RsaKeyStoreProperties(DataSource.instance, 2))) {
                val createdRsaKeys = read()
                val readKeys = read()
                readKeys shouldNotBe null
                createdRsaKeys.currentKey shouldBe readKeys.currentKey
                createdRsaKeys.previousKey shouldBe readKeys.previousKey
                createdRsaKeys.nextKey shouldBe readKeys.nextKey
            }
        }
    }
}
