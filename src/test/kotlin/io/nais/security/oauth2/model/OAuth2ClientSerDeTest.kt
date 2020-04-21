package io.nais.security.oauth2.model

import io.nais.security.oauth2.token.JwtTokenProvider
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

internal class OAuth2ClientSerDeTest {

    @Test
    fun `serialize and deserialize to and from String`() {
        val client = OAuth2Client("myclient", JsonWebKeys(JwtTokenProvider.generateJWKSet("someid", 2048)))
        val json = client.toJson()
        val clientFromJson = OAuth2Client.fromJson(json)
        assertThat(client).isEqualTo(clientFromJson)
    }
}
