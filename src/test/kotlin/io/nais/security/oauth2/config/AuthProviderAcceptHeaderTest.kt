package io.nais.security.oauth2.config

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.junit.jupiter.api.Test

class AuthProviderAcceptHeaderTest {
    @Test
    fun `fromWellKnown should send jwk-set+json Accept header to strict JWKS endpoint`() {
        val rsaKey = RSAKeyGenerator(2048).keyID("test-kid").generate()
        val jwks = JWKSet(rsaKey).toPublicJWKSet()

        val server = MockWebServer()
        server.dispatcher =
            object : Dispatcher() {
                override fun dispatch(request: RecordedRequest): MockResponse =
                    when (request.path) {
                        "/.well-known/openid-configuration" -> {
                            MockResponse()
                                .setBody(
                                    """{"issuer":"${server.url("/")}","jwks_uri":"${server.url("/jwks")}"}""",
                                ).addHeader("Content-Type", "application/json")
                        }

                        "/jwks" -> {
                            val accept = request.getHeader("Accept") ?: ""
                            if ("application/jwk-set+json" !in accept) {
                                MockResponse()
                                    .setResponseCode(406)
                                    .setBody("Not Acceptable: requires application/jwk-set+json")
                            } else {
                                MockResponse()
                                    .setBody(jwks.toString())
                                    .addHeader("Content-Type", "application/jwk-set+json")
                            }
                        }

                        else -> {
                            MockResponse().setResponseCode(404)
                        }
                    }
            }
        server.start()

        try {
            val provider = AuthProvider.fromWellKnown(server.url("/.well-known/openid-configuration").toString())

            // Triggers the actual HTTP GET to /jwks via JwkProviderBuilder.
            // Without the Accept header fix, the strict server returns 406 and this throws.
            val jwk = provider.jwkProvider.get("test-kid")
            jwk.id shouldBe "test-kid"
            jwk.publicKey shouldNotBe null
        } finally {
            server.shutdown()
        }
    }
}
