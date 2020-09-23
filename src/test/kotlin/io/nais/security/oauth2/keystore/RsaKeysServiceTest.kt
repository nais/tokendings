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
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.collections.ArrayList

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
    @Throws(InterruptedException::class)
    fun `rotation of keys executed with concurrency`() {
        val rotationInterval: Long = 2
        withMigratedDb {
            with(rsaKeyStoreService(rotationInterval)) {
                val numberOfThreads = 4
                val exceptions = Collections.synchronizedList(ArrayList<Throwable>())
                val service = Executors.newFixedThreadPool(10)
                try {
                    val afterInitBlocker = CountDownLatch(1)
                    val latch = CountDownLatch(numberOfThreads)

                    val initialKeys: RsaKeys = getAndRotateKeys(rotationInterval)
                    runBlocking { delay(timeMillis = 2000) }

                    for (i in 0 until numberOfThreads) {
                        service.submit {
                            try {
                                afterInitBlocker.await()
                                getAndRotateKeys(rotationInterval)
                            } catch (e: InterruptedException) {
                                exceptions.add(e)
                            } finally {
                                latch.countDown()
                            }
                        }
                    }
                    afterInitBlocker.countDown()
                    val afterInitialKeys = getAndRotateKeys(rotationInterval)
                    initialKeys.currentKey shouldBe afterInitialKeys.previousKey
                    initialKeys.nextKey shouldBe afterInitialKeys.currentKey
                    initialKeys.nextKey shouldNotBe afterInitialKeys.nextKey
                } finally {
                    service.shutdownNow()
                }
                assert(exceptions.isEmpty()) { "failed with exception(s)$exceptions" }
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
