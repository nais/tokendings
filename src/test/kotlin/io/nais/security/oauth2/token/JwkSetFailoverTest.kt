package io.nais.security.oauth2.token

import com.nimbusds.jose.util.DefaultResourceRetriever
import io.kotest.matchers.shouldBe
import io.nais.security.oauth2.mock.withMockOAuth2Server
import kotlinx.coroutines.DelicateCoroutinesApi
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import no.nav.security.mock.oauth2.MockOAuth2Server
import no.nav.security.mock.oauth2.OAuth2Config
import org.intellij.lang.annotations.Language
import org.junit.After
import org.junit.Before
import org.junit.jupiter.api.Test

@OptIn(ExperimentalCoroutinesApi::class, DelicateCoroutinesApi::class)
class JwkSetFailoverTest {
    private val dispatcher = UnconfinedTestDispatcher()
    private val scope = TestScope(dispatcher)

    @Before
    fun setUp() {
        Dispatchers.setMain(dispatcher)
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
    }

    @Test
    fun `failover returns the initial cached jwkset and tries async to update failover cache`() {
        withMockOAuth2Server {
            val jwksUri = this.jwksUrl("issuer1").toUrl()
            val resourceRetriever = DefaultResourceRetriever(200, 20)
            val jwksFailOver = JwkSetFailover(
                TestData.initialJwksSet,
                jwksUri,
                FailoverOptions(1, resourceRetriever, 30, 60)
            )
            jwksFailOver.updateJwkSetResourceAsync(scope)
            val expectedJwkSet = TestData.initialJwksSet.toJwkSet()
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

    @Test
    fun `failover returns the new set of updated keys`() {
        val serverMock = MockOAuth2Server(OAuth2Config.fromJson(TestData.signingJsonSpecified))
        val jwksUri = serverMock.jwksUrl("issuer1").toUrl()
        val resourceRetriever = DefaultResourceRetriever(400, 200)
        val jwksFailOver = JwkSetFailover(
            TestData.initialJwksSet,
            jwksUri,
            FailoverOptions(2, resourceRetriever, 30, 60)
        )
        jwksFailOver.updateJwkSetResourceAsync(scope)
        val expectedJwkSet = TestData.initialJwksSet.toJwkSet()
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

internal fun failOnNull(): Nothing = throw AssertionError("Value should not be null")

internal object TestData {
    const val initialJwksSet =
        "{\"keys\":[{\"kty\":\"RSA\"," +
            "\"e\":\"AQAB\"," +
            "\"use\":\"sig\"," +
            "\"kid\":\"issuer1\"," +
            "\"n\":\"onZcB1ryWS1keTIcbgsLKJ1UBwL1Wbzse5P" +
            "2HjkrNwbG3Jy2lefUEcTVJxN8bpLeW460Luz3ScZd3d9p8" +
            "IoHjmhZ2cyO49E41aBRIlBRzWNpebK5xeC95rSKenYHpOPl" +
            "LzPgybg2qxallzQUOcKCheiF0fsErlapaA9YmKwzP3DwvzYW4J" +
            "qSrHhDGWPwUCcsR4dpetwKXP_9tRFso06ryr4um3qiq7giyZEyZV" +
            "G3fHMplD-5e-2-RrzBiGFW_zvs-XVRGPIf9Y5YNjeQJRuS4vF82V8mNZ" +
            "xEZddtUY5plSz-vgX3GSvANLDH-LZJ76Zmx3a8dEZbI7VxgsBQAqcUlQ\"}]}\n"

    @Language("json")
    val signingJsonSpecified = """
        {
        "tokenProvider" : {
            "keyProvider" : {
               "initialKeys" : "{\"kty\":\"RSA\",\"e\":\"AQAB\",\"use\":\"sig\",\"kid\":\"issuer1\",\"n\":\"onZcB1ryWS1keTIcbgsLKJ1UBwL1Wbzse5P2HjkrNwbG3Jy2lefUEcTVJxN8bpLeW460Luz3ScZd3d9p8IoHjmhZ2cyO49E41aBRIlBRzWNpebK5xeC95rSKenYHpOPlLzPgybg2qxallzQUOcKCheiF0fsErlapaA9YmKwzP3DwvzYW4JqSrHhDGWPwUCcsR4dpetwKXP_9tRFso06ryr4um3qiq7giyZEyZVG3fHMplD-5e-2-RrzBiGFW_zvs-XVRGPIf9Y5YNjeQJRuS4vF82V8mNZxEZddtUY5plSz-vgX3GSvANLDH-LZJ76Zmx3a8dEZbI7VxgsBQAqcUlQ\"}",
               "algorithm" : "RS256"
            }
          }
        }
    """.trimIndent()
}
