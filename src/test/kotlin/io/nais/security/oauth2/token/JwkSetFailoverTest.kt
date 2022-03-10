package io.nais.security.oauth2.token

import com.nimbusds.jose.jwk.JWKMatcher
import com.nimbusds.jose.jwk.JWKSelector
import com.nimbusds.jose.util.DefaultResourceRetriever
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.nais.security.oauth2.mock.withMockOAuth2Server
import io.nais.security.oauth2.utils.generateRsaKey
import kotlinx.coroutines.DelicateCoroutinesApi
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import no.nav.security.mock.oauth2.MockOAuth2Server
import no.nav.security.mock.oauth2.OAuth2Config
import no.nav.security.mock.oauth2.http.objectMapper
import okhttp3.internal.wait
import org.intellij.lang.annotations.Language
import org.junit.After
import org.junit.Before
import org.junit.jupiter.api.Test

@OptIn(ExperimentalCoroutinesApi::class, DelicateCoroutinesApi::class)
class JwkSetFailoverTest {
    private val dispatcher = UnconfinedTestDispatcher(name = "JwkSetFailoverTest")
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
    fun `failover returns the initial cached jwk set`() {
        withMockOAuth2Server {
            val jwksUri = this.jwksUrl("issuer1").toUrl()
            val resourceRetriever = DefaultResourceRetriever(1000, 100)
            val jwksFailoverSource = JwkSetFailover(
                resourceRetriever.retrieveResource(jwksUri).content,
                jwksUri.toString(),
                FailoverOptions(
                    2,
                    resourceRetriever,
                    100,
                    200,
                    scope
                )
            )
            this.shutdown()
            val expectedJwkSet = jwksFailoverSource.getJwkSet()
            scope.launch {
                jwksFailoverSource.updateJwkSetResourceAsync()
            }
            val result = jwksFailoverSource.getJwkSet()
            expectedJwkSet?.keys ?: failOnNull()
            result?.keys ?: failOnNull()
            expectedJwkSet.keys.size shouldBe result.keys.size

            expectedJwkSet.keys?.forEach { expected ->
                expectedJwkSet.keys?.forEach { got ->
                    expected.keyID shouldBe got.keyID
                    expected.keyType shouldBe got.keyType
                }
            }
        }
    }

    @Test
    fun `failover returns the updated jwk set`() {
        val issuer = "issuer2"
        val generatedPublicJwkSet = TestData.signingJsonSpecified(
            objectMapper.writeValueAsString(
                generateRsaKey(keyId = issuer).toPublicJWK().toString()
            )
        )
        val oauth2Config = OAuth2Config.fromJson(generatedPublicJwkSet)
        val serverMock = MockOAuth2Server(oauth2Config)
        serverMock.start()
        val jwksUri = serverMock.jwksUrl(issuer).toUrl()
        val resourceRetriever = DefaultResourceRetriever(1000, 500)
        val jwksSource = JwkSetFailover(
            // Initial jwk set is "issuer1"
            TestData.initialJwksSet,
            jwksUri.toString(),
            FailoverOptions(
                times = 5,
                resourceRetriever = resourceRetriever,
                coroutineScope = scope
            )
        )
        val initialJwkSet = jwksSource.getJwkSet()
        jwksSource.get(JWKSelector(JWKMatcher.Builder().keyID(issuer).build()), null)
        val updatedJwkSet = jwksSource.getJwkSet()
        initialJwkSet ?: failOnNull()
        updatedJwkSet ?: failOnNull()
        initialJwkSet.keys[0].keyID shouldNotBe updatedJwkSet.keys[0].keyID
        serverMock.shutdown()
    }
}

private fun failOnNull(): Nothing = throw AssertionError("Value should not be null")

private object TestData {
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
    fun signingJsonSpecified(key: String) = """
        {
        "tokenProvider" : {
            "keyProvider" : {
               "initialKeys" : $key,
               "algorithm" : "RS256"
            }
          }
        }
    """.trimIndent()
}
