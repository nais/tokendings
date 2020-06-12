package io.nais.security.oauth2.model

import com.nimbusds.oauth2.sdk.`as`.AuthorizationServerMetadata
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata
import io.nais.security.oauth2.Jackson
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

internal class WellKnownTest {

    val mapper = Jackson.defaultMapper

    @Test
    fun `WellKnown data class should parse as valid OAuth2 Authorization Server metadata`() {
        val issuerUrl = "http://localhost"
        val wellKnown = WellKnown(
            issuer = issuerUrl,
            authorizationEndpoint = "$issuerUrl/authorize",
            tokenEndpoint = "$issuerUrl/token",
            jwksUri = "$issuerUrl/jwks"
        )
        assertThat(AuthorizationServerMetadata.parse(mapper.writeValueAsString(wellKnown))).isNotNull
        assertThat(OIDCProviderMetadata.parse(mapper.writeValueAsString(wellKnown))).isNotNull
    }
}
