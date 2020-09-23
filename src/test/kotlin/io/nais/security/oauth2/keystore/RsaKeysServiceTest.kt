package io.nais.security.oauth2.keystore

import com.nimbusds.jose.jwk.RSAKey
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.nais.security.oauth2.mock.rsaKeyStoreService
import io.nais.security.oauth2.mock.withMigratedDb
import junit.framework.Assert.assertTrue
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.awaitility.Awaitility
import org.junit.Before
import org.junit.jupiter.api.Test
import java.util.*
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
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
    @Throws(InterruptedException::class)
    fun `rotation of keys executed with concurrency`() {
        withMigratedDb {
            val rsaKeyService = rsaKeyStoreService(2)
            val numberOfThreads = 4
            val exceptions = Collections.synchronizedList(ArrayList<Throwable>())
            val service = Executors.newFixedThreadPool(10)
            try {
                val afterInitBlocker = CountDownLatch(1)
                val latch = CountDownLatch(numberOfThreads)

                val initialKey: RSAKey = rsaKeyService.currentSigningKey
                runBlocking { delay(timeMillis = 2000) }
                val afterInitialKey: RSAKey = rsaKeyService.currentSigningKey

                for (i in 0 until numberOfThreads) {
                    service.submit {
                        try {
                            afterInitBlocker.await()
                            rsaKeyService.currentSigningKey
                        } catch (e: InterruptedException) {
                            exceptions.add(e)
                        } finally {
                            latch.countDown()
                        }
                    }
                }
                afterInitBlocker.countDown()
                println(initialKey)
                println(afterInitialKey)
                println(rsaKeyService.currentSigningKey)
            } finally {
                service.shutdownNow();
            }
            assertTrue("failed with exception(s)$exceptions", exceptions.isEmpty())
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
