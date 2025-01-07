package io.nais.security.oauth2.model

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.Payload
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.JWTClaimsSet
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.nais.security.oauth2.token.sign
import io.nais.security.oauth2.utils.generateRsaKey
import org.junit.jupiter.api.Test

internal class ClientRegistrationKtTest {
    @Test
    fun `softwarestatement should successfully verify and parse into SoftwareStatement`() {
        val signingKey = generateRsaKey()

        val ss =
            JWTClaimsSet
                .Builder()
                .claim("appId", "app1")
                .claim("accessPolicyInbound", emptyList<String>())
                .claim("accessPolicyOutbound", emptyList<String>())
                .build()
                .sign(signingKey)
        val request =
            ClientRegistrationRequest(
                "name",
                JsonWebKeys(JWKSet(generateRsaKey())),
                ss.serialize(),
            )

        request.verifySoftwareStatement(JWKSet(signingKey)) shouldBe SoftwareStatement("app1", emptyList(), emptyList())
    }

    @Test
    fun `softwarestatement with null values`() {
        val signingKey = generateRsaKey()
        val ss =
            JWSObject(
                JWSHeader.Builder(JWSAlgorithm.RS256).keyID(signingKey.keyID).build(),
                Payload(
                    """
                    {
                      "appId": "cluster:ns:app1",
                      "accessPolicyInbound": null,
                      "accessPolicyOutbound": [
                        "cluster:ns:app2"
                      ]
                    }
                    """.trimIndent(),
                ),
            ).apply {
                sign(RSASSASigner(signingKey))
            }

        val request =
            ClientRegistrationRequest(
                "name",
                JsonWebKeys(JWKSet(generateRsaKey())),
                ss.serialize(),
            )
        request.verifySoftwareStatement(JWKSet(signingKey)) shouldBe SoftwareStatement("cluster:ns:app1", emptyList(), listOf("cluster:ns:app2"))

        val ss2 =
            JWSObject(
                JWSHeader.Builder(JWSAlgorithm.RS256).keyID(signingKey.keyID).build(),
                Payload(
                    """
                    {
                      "appId": null,
                      "accessPolicyInbound": null,
                      "accessPolicyOutbound": [
                        "cluster:ns:app2"
                      ]
                    }
                    """.trimIndent(),
                ),
            ).apply {
                sign(RSASSASigner(signingKey))
            }

        shouldThrow<OAuth2Exception> {
            ClientRegistrationRequest(
                "name",
                JsonWebKeys(JWKSet(generateRsaKey())),
                ss2.serialize(),
            ).verifySoftwareStatement(JWKSet(signingKey))
        }
    }
}
