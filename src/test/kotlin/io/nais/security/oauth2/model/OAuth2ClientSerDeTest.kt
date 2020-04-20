package io.nais.security.oauth2.model

import com.fasterxml.jackson.annotation.JsonIgnore
import com.fasterxml.jackson.databind.SerializationFeature
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import com.nimbusds.jose.jwk.JWKSet
import io.nais.security.oauth2.token.JwtTokenProvider
import net.minidev.json.JSONObject
import org.junit.jupiter.api.Test
import java.time.Duration
import java.time.Instant

// TODO: add tests to ensure nothing breaks when upgrading nimbus etc
internal class OAuth2ClientSerDeTest {

    data class TestJwks(
        val jwks: JSONObject
    ) {
        @JsonIgnore
        val jwkSet: JWKSet = JWKSet.parse(jwks.toJSONString())
    }

    @Test
    fun test() {
        val mapper = jacksonObjectMapper()
        val json = measureTime {
            mapper.enable(SerializationFeature.INDENT_OUTPUT).writeValueAsString(
                TestJwks(
                    JwtTokenProvider.generateJWKSet("someid", 2048).toJSONObject()
                )
            )
        }

        val test: TestJwks = mapper.readValue(json)
    }

    @Test
    fun `serialize and deserialize to and from String`() {

        val client = OAuth2Client("myclient", JsonWebKeySet(JwtTokenProvider.generateJWKSet("someid", 2048)))
        val mapper = jacksonObjectMapper()
        val json = measureTime {
            mapper.enable(SerializationFeature.INDENT_OUTPUT).writeValueAsString(client)
        }
        val client2 = OAuth2Client("myclient2", JsonWebKeySet(JwtTokenProvider.generateJWKSet("someid", 2048)))
        measureTime {
            mapper.enable(SerializationFeature.INDENT_OUTPUT).writeValueAsString(client2)
        }
        measureTime {
            mapper.readValue<OAuth2Client>(json)
        }
        measureTime {
            mapper.readValue<OAuth2Client>(json)
        }
    }

    private inline fun <reified R : Any?> measureTime(block: () -> R): R {
        val start = Instant.now()
        try {
            return block()
        } finally {
            val duration = Duration.between(start, Instant.now())
            println("execution took ${duration.toMillis()} ms")
        }
    }
}
