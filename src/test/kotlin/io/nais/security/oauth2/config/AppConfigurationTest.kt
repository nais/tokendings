package io.nais.security.oauth2.config

import com.nimbusds.jose.jwk.JWKSet
import io.kotest.assertions.throwables.shouldThrow
import org.junit.jupiter.api.Test
import java.nio.file.Files
import java.nio.file.Path

class AppConfigurationTest {
    @Test
    fun `get authprovider from self signed should be successful`() {
        val jwks = JWKSet.parse(Files.readString(Path.of("src/test/resources/jwker-jwks.json")))
        AuthProvider.fromSelfSigned("myissuer", jwks)
    }

    @Test
    fun `get authprovider from self signed should fail if keys not correctly formatted`() {
        val jwks = JWKSet.parse(Files.readString(Path.of("src/test/resources/jwker-jwks-fail.json")))
        shouldThrow<IllegalArgumentException> {
            AuthProvider.fromSelfSigned("myissuer", jwks)
        }
    }
}
