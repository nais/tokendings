package io.nais.security.oauth2.rsakeystore

import io.kotest.matchers.shouldBe
import io.nais.security.oauth2.mock.DataSource
import io.nais.security.oauth2.mock.withMigratedDb
import org.awaitility.Awaitility
import org.junit.Before
import org.junit.jupiter.api.Test
import java.util.concurrent.TimeUnit

class RSAKeysServiceTest {

    @Before
    fun setup() {
        Awaitility.reset()
    }

    @Test
    fun `signing key from local cache should be equal to database keystore`() {
        withMigratedDb {
            with(KeyStore(DataSource.instance)) {
                val keystoreService = RSAKeysService(keyStore = this)
                val keys = this.keys()
                Awaitility
                    .await().atMost(1, TimeUnit.SECONDS)
                    .until {
                        keystoreService.currentSigningKey == keys.currentKey
                    }
            }
        }
    }

    @Test
    fun `jwks endpoint should return current and previous key in public format`() {
        withMigratedDb {
            with(KeyStore(DataSource.instance)) {
                val keystoreService = RSAKeysService(keyStore = this)
                keystoreService.resetKeys()
                val currentPublicKey = keystoreService.publicJWKSet.keys[0]
                val previousPublicKey = keystoreService.publicJWKSet.keys[1]
                keystoreService.publicJWKSet.keys.size shouldBe 2
                currentPublicKey shouldBe keys().currentKey.toPublicJWK()
                currentPublicKey.isPrivate shouldBe false
                previousPublicKey shouldBe keys().previousKey.toPublicJWK()
                previousPublicKey.isPrivate shouldBe false
            }
        }
    }
}
