package io.nais.security.oauth2.keystore

import com.nimbusds.jose.jwk.RSAKey
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.nais.security.oauth2.mock.rsaKeyStoreService
import io.nais.security.oauth2.mock.withMigratedDb
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.awaitility.Awaitility
import org.junit.Before
import org.junit.jupiter.api.Test
import java.util.concurrent.TimeUnit

class RsaKeysServiceTest {

    @Before
    fun setup() {
        Awaitility.reset()
    }

    @Test
    fun `signing key from local cache should be equal to database keystore`() {
        withMigratedDb {
            with(rsaKeyStoreService(2)) {
                val currentKey = this.currentSigningKey
                Awaitility
                    .await().atMost(1, TimeUnit.SECONDS)
                    .until {
                        this.currentSigningKey == currentKey
                    }
            }
        }
    }

    @Test
    fun `currentSigningKey should check for expiry, read from keystore and rotate if neccessary`() {

        withMigratedDb {
            val rsaKeyService = rsaKeyStoreService(2)
            val firstSigningKey: RSAKey = rsaKeyService.currentSigningKey
            runBlocking {
                rsaKeyService.currentSigningKey shouldBe firstSigningKey
                delay(timeMillis = 2000)
                val secondSigningKey: RSAKey = rsaKeyService.currentSigningKey
                firstSigningKey shouldNotBe secondSigningKey
            }
        }
    }


    @Test
    fun `jwks endpoint should return current and previous key in public format`() {
        withMigratedDb {
            with(rsaKeyStoreService(2)) {
                val currentPublicKey = this.publicJWKSet.keys[0]
                val previousPublicKey = this.publicJWKSet.keys[1]
                currentPublicKey.isPrivate shouldBe false
                previousPublicKey.isPrivate shouldBe false
                this.publicJWKSet.keys.size shouldBe 2
                this.publicJWKSet.keys[0] shouldBe currentPublicKey
                this.publicJWKSet.keys[1] shouldBe previousPublicKey
            }
        }
    }
}
