package io.nais.security.oauth2.token

import com.nimbusds.jose.util.DefaultResourceRetriever
import io.kotest.matchers.shouldBe
import io.nais.security.oauth2.mock.withMockOAuth2Server
import kotlinx.coroutines.DelicateCoroutinesApi
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.newSingleThreadContext
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Before
import org.junit.jupiter.api.Test

@OptIn(ExperimentalCoroutinesApi::class, DelicateCoroutinesApi::class)
class JwkSetFailOverTest {
    private val mainThreadSurrogate = newSingleThreadContext("UI thread")

    @Before
    fun setUp() {
        Dispatchers.setMain(mainThreadSurrogate)
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
        mainThreadSurrogate.close()
    }

    @Test
    fun `failover returns the initial cached jwkset and tries async to update failover cache`() {
        withMockOAuth2Server {
            val jwksUri = this.jwksUrl("issuer1").toUrl()
            val resourceRetriever = DefaultResourceRetriever(200, 20)
            val jwksFailOver = JwkSetFailOver(
                initialJwksSet,
                jwksUri,
                resourceRetriever,
                RetryOptions(1, 30, 60)
            )
            jwksFailOver.updateJwkSetResourceAsync()
            val expectedJwkSet = initialJwksSet.toJwkSet()
            val result = jwksFailOver.getJwkSet()
            expectedJwkSet?.keys ?: failOnNull()
            result?.keys ?: failOnNull()
            expectedJwkSet.keys.size shouldBe result.keys.size

            jwksFailOver.getJwkSet()?.keys?.forEach {
                val e = expectedJwkSet.keys[0]
                e.keyID shouldBe it.keyID
                e.keyType shouldBe it.keyType
            }
        }
    }
}

fun failOnNull(): Nothing = throw AssertionError("Value should not be null")

const val initialJwksSet =
    "{\"keys\"" +
        ":[{\"kty\":\"RSA\"" +
        ",\"e\":\"AQAB\"," +
        "\"use\":\"sig\"," +
        "\"kid\":\"issuer1\"," +
        "\"n\":\"onZcB1ryWS1keTIcbgsLKJ1UBwL1Wbzse5P2HjkrNwb" +
        "G3Jy2lefUEcTVJxN8bpLeW460Luz3ScZd3d9p8IoHjmhZ2cyO49E41aB" +
        "RIlBRzWNpebK5xeC95rSKenYHpOPlLzPgybg2qxallzQUOcKCheiF0fsErl" +
        "apaA9YmKwzP3DwvzYW4JqSrHhDGWPwUCcsR4dpetwKXP_9tRFso06ryr4um3qiq" +
        "7giyZEyZVG3fHMplD-5e-2-RrzBiGFW_zvs-XVRGPIf9Y5YNjeQJRuS4vF82V8mNZxE" +
        "ZddtUY5plSz-vgX3GSvANLDH-LZJ76Zmx3a8dEZbI7VxgsBQAqcUlQ\"}]}\n"
