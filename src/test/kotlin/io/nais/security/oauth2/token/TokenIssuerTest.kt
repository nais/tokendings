package io.nais.security.oauth2.token

import io.kotest.matchers.maps.shouldContainAll
import io.kotest.matchers.shouldBe
import io.ktor.util.*
import io.nais.security.oauth2.config.AuthorizationServerProperties
import io.nais.security.oauth2.config.SubjectTokenIssuer
import io.nais.security.oauth2.keystore.MockRotatingKeyStore
import io.nais.security.oauth2.keystore.RotatingKeyStore
import io.nais.security.oauth2.mock.rotatingKeyStore
import io.nais.security.oauth2.mock.withMockOAuth2Server
import io.nais.security.oauth2.model.JsonWebKeys
import io.nais.security.oauth2.model.OAuth2Client
import io.nais.security.oauth2.model.OAuth2TokenExchangeRequest
import io.nais.security.oauth2.model.SubjectTokenType
import io.nais.security.oauth2.utils.jwkSet
import io.nais.security.oauth2.utils.mockkFuture
import io.nais.security.oauth2.utils.verifySignature
import no.nav.security.mock.oauth2.MockOAuth2Server
import no.nav.security.mock.oauth2.token.DefaultOAuth2TokenCallback
import org.junit.jupiter.api.Test
import java.time.Duration

@KtorExperimentalAPI
internal class TokenIssuerTest {

    @Test
    fun `issue token for token exchange request should return token containing same claims as subject token and added claims`() {
        withMockOAuth2Server {
            val subjectTokenIdp: String = this.issuerUrl("issuer1").toString()
            val subjectToken = this.createSubjectToken(
                "thesubject",
                mapOf(
                    "claim1" to "claim1value",
                    "claim2" to "claim2value"
                )
            ).serialize()
            val fakeKeyStore = MockRotatingKeyStore()

            with(tokenIssuer(mockOAuth2Server = this, rotatingKeyStore = fakeKeyStore)) {
                val oAuth2Client = oAuth2Client()
                val tokenAudience = "jollo"
                val issuedToken = issueTokenFor(
                    oAuth2Client,
                    tokenExchangeRequest(subjectToken, tokenAudience)
                )
                issuedToken.verifySignature(this.publicJwkSet()).claims shouldContainAll mapOf(
                    Pair("sub", "thesubject"),
                    Pair("claim1", "claim1value"),
                    Pair("claim2", "claim2value"),
                    Pair("client_id", oAuth2Client.clientId),
                    Pair("idp", subjectTokenIdp),
                    Pair("iss", ISSUER_URL),
                    Pair("aud", listOf(tokenAudience))
                )
            }
        }
    }

    @Test
    fun `exchanged token should keep idp claim if already present in subject_token`() {
        withMockOAuth2Server {
            val subjectToken = this.createSubjectToken(
                "thesubject",
                mapOf(
                    "claim1" to "claim1value",
                    "claim2" to "claim2value",
                    "idp" to "http://originalidp"
                )
            ).serialize()
            val fakeKeyStore = MockRotatingKeyStore()

            with(tokenIssuer(mockOAuth2Server = this, rotatingKeyStore = fakeKeyStore)) {
                val oAuth2Client = oAuth2Client()
                val tokenAudience = "jollo"
                val issuedToken = issueTokenFor(
                    oAuth2Client,
                    tokenExchangeRequest(subjectToken, "aud")
                )
                issuedToken.verifySignature(this.publicJwkSet()).claims["idp"] shouldBe "http://originalidp"
            }
        }
    }

    @Test
    fun `token can be verified even though keys have rotated`() {
        withMockOAuth2Server {
            val subjectToken = this.createSubjectToken(
                "thesubject"
            ).serialize()
            val fakeKeyStore = MockRotatingKeyStore()
            val tokenIssuer = tokenIssuer(mockOAuth2Server = this, rotatingKeyStore = fakeKeyStore)
            var issuedToken = tokenIssuer.issueTokenFor(
                oAuth2Client(),
                tokenExchangeRequest(subjectToken, "aud1")
            )
            // simulate 3 key rotations
            repeat(3) {
                mockkFuture(Duration.ofDays(1).plusMinutes(1))
                issuedToken = tokenIssuer.issueTokenFor(
                    oAuth2Client(),
                    tokenExchangeRequest(issuedToken.serialize(), "aud$it")
                )
                issuedToken.verifySignature(tokenIssuer.publicJwkSet())
            }
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

    private fun tokenIssuer(mockOAuth2Server: MockOAuth2Server? = null, rotatingKeyStore: RotatingKeyStore? = null) =
        if (mockOAuth2Server != null) {
            TokenIssuer(
                AuthorizationServerProperties(
                    ISSUER_URL,
                    listOf(
                        SubjectTokenIssuer(mockOAuth2Server.wellKnownUrl("issuer1").toString()),
                        SubjectTokenIssuer(mockOAuth2Server.wellKnownUrl("issuer2").toString())
                    ),
                    300,
                    rotatingKeyStore ?: rotatingKeyStore()
                )
            )
        } else {
            TokenIssuer(
                AuthorizationServerProperties(
                    ISSUER_URL,
                    emptyList(),
                    300,
                    rotatingKeyStore ?: rotatingKeyStore()
                )
            )
        }

    companion object {
        private const val ISSUER_URL = "http://localhost/thisissuer"
    }
}
