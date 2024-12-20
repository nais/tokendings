package io.nais.security.oauth2.keystore

import com.nimbusds.jose.jwk.RSAKey
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.nais.security.oauth2.mock.rotatingKeyStore
import io.nais.security.oauth2.mock.withMigratedDb
import io.nais.security.oauth2.utils.mockkFuture
import org.junit.jupiter.api.Test
import java.time.Duration
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors

class RotatingKeyStorePostgresTest {
    @Test
    fun `signing key should not be rotated`() {
        withMigratedDb {
            with(rotatingKeyStore()) {
                val currentKey = this.currentSigningKey()
                mockkFuture(Duration.ofHours(23))
                this.currentSigningKey() shouldBe currentKey
            }
        }
    }

    @Test
    fun `invoking currentSigningKey should check for expiry, read from keystore and rotate if accessed after one day`() {
        withMigratedDb {
            val rsaKeyService = rotatingKeyStore(Duration.ofDays(1))
            val firstSigningKey: RSAKey = rsaKeyService.currentSigningKey()
            rsaKeyService.currentSigningKey() shouldBe firstSigningKey

            mockkFuture(Duration.ofDays(1).plusMinutes(1))

            val rotatedSigningKey: RSAKey = rsaKeyService.currentSigningKey()
            rotatedSigningKey shouldNotBe firstSigningKey
        }
    }

    @Test
    fun `jwks endpoint should return current and previous key in public format`() {
        withMigratedDb {
            with(rotatingKeyStore()) {
                val currentPublicKey = this.publicJWKSet().keys[0]
                val previousPublicKey = this.publicJWKSet().keys[1]
                currentPublicKey.isPrivate shouldBe false
                previousPublicKey.isPrivate shouldBe false
                this.publicJWKSet().keys.size shouldBe 2
                this.publicJWKSet().keys[0] shouldBe currentPublicKey
                this.publicJWKSet().keys[1] shouldBe previousPublicKey
            }
        }
    }

    @Test
    @Throws(InterruptedException::class)
    fun `rotation of rsa keys executed with n threads concurrency`() {
        val rotationInterval = Duration.ofSeconds(2)
        withMigratedDb {
            with(rotatingKeyStore(rotationInterval)) {
                val numberOfThreads = 4
                val service = Executors.newFixedThreadPool(10)
                val latch = CountDownLatch(numberOfThreads)
                val initialKey: RSAKey = currentSigningKey()
                mockkFuture(rotationInterval)

                repeat(numberOfThreads) {
                    service.submit {
                        try {
                            val rotatedKey = currentSigningKey()
                            publicJWKSet().containsJWK(rotatedKey) shouldBe true
                            publicJWKSet().containsJWK(initialKey) shouldBe true
                        } finally {
                            latch.countDown()
                        }
                    }
                }
                latch.await()
                service.shutdownNow()
            }
        }
    }
}
