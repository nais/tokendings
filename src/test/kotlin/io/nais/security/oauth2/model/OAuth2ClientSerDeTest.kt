package io.nais.security.oauth2.model

import io.nais.security.oauth2.utils.jwkSet
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

internal class OAuth2ClientSerDeTest {
    @Test
    fun `serialize and deserialize to and from String`() {
        val client =
            OAuth2Client(
                clientId = "jwker",
                jwks = JsonWebKeys(jwkSet()),
                allowedScopes = listOf("http://localhost:8080/client/registration"),
                allowedGrantTypes = listOf(GrantType.CLIENT_CREDENTIALS_GRANT),
            )
        val json = client.toJson()
        val clientFromJson = OAuth2Client.fromJson(json)
        assertThat(client).isEqualTo(clientFromJson)
    }
}
