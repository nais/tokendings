package io.nais.security.oauth2

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.nimbusds.oauth2.sdk.`as`.AuthorizationServerMetadata
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata
import io.nais.security.oauth2.config.TokenIssuerConfig.Companion.authorizationPath
import io.nais.security.oauth2.config.TokenIssuerConfig.Companion.jwksPath
import io.nais.security.oauth2.config.TokenIssuerConfig.Companion.tokenPath
import io.nais.security.oauth2.config.path
import io.nais.security.oauth2.model.WellKnown
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

internal class WellKnownTest {

    val mapper = jacksonObjectMapper()

    @Test
    fun `WellKnown data class should parse as valid OAuth2 Authorization Server metadata`() {
        val issuerUrl = "http://localhost"
        val wellKnown = WellKnown(
            issuer = issuerUrl,
            authorizationEndpoint = issuerUrl.path(authorizationPath),
            tokenEndpoint = issuerUrl.path(tokenPath),
            jwksUri = issuerUrl.path(jwksPath)
        )
        assertThat(AuthorizationServerMetadata.parse(mapper.writeValueAsString(wellKnown))).isNotNull
        assertThat(OIDCProviderMetadata.parse(mapper.writeValueAsString(wellKnown))).isNotNull
    }
}
