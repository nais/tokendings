package io.nais.security.oauth2.token

import com.nimbusds.jose.jwk.JWKSet
import io.kotest.matchers.maps.shouldContain

import io.nais.security.oauth2.config.AuthorizationServerProperties
import io.nais.security.oauth2.config.SubjectTokenIssuer
import io.nais.security.oauth2.mock.withMockOAuth2Server
import io.nais.security.oauth2.model.JsonWebKeys
import io.nais.security.oauth2.model.OAuth2Client
import io.nais.security.oauth2.model.OAuth2TokenExchangeRequest
import io.nais.security.oauth2.model.SubjectTokenType
import io.nais.security.oauth2.utils.generateRsaKey
import io.nais.security.oauth2.utils.jwkSet
import io.nais.security.oauth2.utils.verifySignature
import no.nav.security.mock.oauth2.MockOAuth2Server
import no.nav.security.mock.oauth2.token.DefaultOAuth2TokenCallback
import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.Test

internal class TokenIssuerTest {

    @Test
    fun `issue token for token exchange request should return token with same claims as subjecttoken`() {
        withMockOAuth2Server {
            val subjectToken = this.createSubjectToken(
                "thesubject",
                mapOf(
                    "claim1" to "claim1value",
                    "claim2" to "claim2value"
                )
            ).serialize()
            with(tokenIssuer(this)) {
                val issuedToken = issueTokenFor(
                    oAuth2Client(),
                    tokenExchangeRequest(subjectToken, "desired audience for token")
                )
                issuedToken.jwtClaimsSet.claims shouldContain Pair("sub", "thesubject")
                issuedToken.jwtClaimsSet.claims shouldContain Pair("claim1", "claim1value")
                issuedToken.jwtClaimsSet.claims shouldContain Pair("claim2", "claim2value")
            }
        }
    }

    @Disabled("add back in when key rotation is implemented")
    @Test
    fun `token can be verified even though keys have rotated`() {
        withMockOAuth2Server {
            val subjectToken = this.createSubjectToken(
                "thesubject"
            ).serialize()
            val tokenIssuer = tokenIssuer(this)
            val tokenIssuerRestarted = tokenIssuer(this)
            val issuedToken = tokenIssuer.issueTokenFor(
                oAuth2Client(),
                tokenExchangeRequest(subjectToken, "desired audience for token")
            )
            issuedToken.verifySignature(tokenIssuerRestarted.publicJwkSet())
        }
    }

    private fun MockOAuth2Server.createSubjectToken(subject: String, claims: Map<String, Any> = emptyMap()) =
        this.issueToken(
            "issuer1",
            "client_id_random",
            DefaultOAuth2TokenCallback(
                issuerId = "issuer1",
                subject = subject,
                claims = claims
            )
        )

    private fun tokenExchangeRequest(subjectToken: String, audience: String) =
        OAuth2TokenExchangeRequest(
            SubjectTokenType.TOKEN_TYPE_JWT,
            subjectToken,
            audience
        )

    private fun oAuth2Client(): OAuth2Client =
        OAuth2Client(
            "testclient",
            JsonWebKeys(jwkSet())
        )

    private fun tokenIssuer(mockOAuth2Server: MockOAuth2Server? = null) =
        if (mockOAuth2Server != null) {
            TokenIssuer(
                AuthorizationServerProperties(
                    "http://localhost/thisissuer",
                    listOf(
                        SubjectTokenIssuer(mockOAuth2Server.wellKnownUrl("issuer1").toString()),
                        SubjectTokenIssuer(mockOAuth2Server.wellKnownUrl("issuer2").toString())
                    ),
                    300,
                    DefaultKeyStore(JWKSet(generateRsaKey()))
                )
            )
        } else {
            TokenIssuer(
                AuthorizationServerProperties(
                    "http://localhost/thisissuer",
                    emptyList(),
                    300,
                    DefaultKeyStore(JWKSet(generateRsaKey()))
                )
            )
        }
}
