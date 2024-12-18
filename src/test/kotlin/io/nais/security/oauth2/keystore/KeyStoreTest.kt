package io.nais.security.oauth2.keystore

import io.kotest.matchers.shouldBe
import io.nais.security.oauth2.mock.DataSource
import io.nais.security.oauth2.mock.withMigratedDb
import io.nais.security.oauth2.utils.generateRsaKey
import org.junit.jupiter.api.Test
import java.time.LocalDateTime

class KeyStoreTest {
    @Test
    fun `keyStore save() should insert or update new record`() {
        withMigratedDb {
            with(rsaKeyStore()) {
                val readKeys = read()
                readKeys shouldBe null

                val newKeys = newKeys()
                save(newKeys)
                read() shouldBe newKeys

                val updateKeys = newKeys.copy(currentKey = generateRsaKey())
                save(updateKeys)
                read() shouldBe updateKeys
            }
        }
    }

    private fun rsaKeyStore(): KeyStore = KeyStore(DataSource.instance)

    private fun newKeys() =
        RotatableKeys(
            generateRsaKey(),
            generateRsaKey(),
            generateRsaKey(),
            LocalDateTime.now(),
        )
}
