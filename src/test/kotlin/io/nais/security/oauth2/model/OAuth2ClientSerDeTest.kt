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

    @Test
    fun `round-trip preserves federated identity`() {
        val client =
            OAuth2Client(
                clientId = "jwker",
                jwks = JsonWebKeys(jwkSet()),
                federatedIdentity = FederatedIdentity("https://kubernetes.default.svc", "system:serviceaccount:team:app"),
            )
        val roundTripped = OAuth2Client.fromJson(client.toJson())
        assertThat(roundTripped).isEqualTo(client)
        assertThat(roundTripped.federatedIdentity).isEqualTo(client.federatedIdentity)
    }

    @Test
    fun `legacy JSON without federatedIdentity deserializes with null`() {
        // Pre-migration blob as stored in the clients.data JSONB column today.
        val legacyJson =
            OAuth2Client(
                clientId = "jwker",
                jwks = JsonWebKeys(jwkSet()),
            ).toJson()

        val client = OAuth2Client.fromJson(legacyJson)

        assertThat(client.federatedIdentity).isNull()
    }

    @Test
    fun `serialized client omits federatedIdentity when null`() {
        // Prevents mass data churn: every legacy row would otherwise gain a
        // "federatedIdentity": null field on first touch after deploy.
        val json =
            OAuth2Client(
                clientId = "jwker",
                jwks = JsonWebKeys(jwkSet()),
            ).toJson()

        assertThat(json).doesNotContain("federatedIdentity")
    }
}
