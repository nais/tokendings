package io.nais.security.oauth2.model

import com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.nimbusds.oauth2.sdk.`as`.AuthorizationServerMetadata
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

internal class WellKnownTest {
    private val mapper = jacksonObjectMapper()

    @Test
    fun `WellKnown data class should parse as valid OAuth2 Authorization Server metadata`() {
        val issuerUrl = "http://localhost"
        val wellKnown =
            WellKnown(
                issuer = issuerUrl,
                authorizationEndpoint = "$issuerUrl/authorize",
                tokenEndpoint = "$issuerUrl/token",
                jwksUri = "$issuerUrl/jwks",
            )
        assertThat(AuthorizationServerMetadata.parse(mapper.writeValueAsString(wellKnown))).isNotNull
        assertThat(OIDCProviderMetadata.parse(mapper.writeValueAsString(wellKnown))).isNotNull
    }

    @Test
    fun `SubjectTokenIssuerMetadata should parse Maskinporten-style discovery document without authorization_endpoint`() {
        // Mirrors production HTTP client config (TokenExchangeApp.kt: FAIL_ON_UNKNOWN_PROPERTIES=false)
        val httpClientMapper = jacksonObjectMapper().configure(FAIL_ON_UNKNOWN_PROPERTIES, false)

        // Verbatim shape from https://test.maskinporten.no/.well-known/oauth-authorization-server
        val maskinportenJson =
            """
            {
              "authorization_details_types_supported": ["urn:altinn:systemuser", "urn:altinn:consent"],
              "grant_types_supported": ["urn:ietf:params:oauth:grant-type:jwt-bearer"],
              "issuer": "https://test.maskinporten.no/",
              "jwks_uri": "https://test.maskinporten.no/jwk",
              "token_endpoint": "https://test.maskinporten.no/token",
              "token_endpoint_auth_methods_supported": ["private_key_jwt"],
              "token_endpoint_auth_signing_alg_values_supported": ["RS256", "RS384", "RS512"]
            }
            """.trimIndent()

        val metadata = httpClientMapper.readValue(maskinportenJson, SubjectTokenIssuerMetadata::class.java)

        assertThat(metadata.issuer).isEqualTo("https://test.maskinporten.no/")
        assertThat(metadata.jwksUri).isEqualTo("https://test.maskinporten.no/jwk")
    }
}
