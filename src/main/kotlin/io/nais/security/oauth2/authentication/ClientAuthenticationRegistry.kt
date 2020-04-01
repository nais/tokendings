package io.nais.security.oauth2.authentication

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod
import io.ktor.auth.Credential
import io.ktor.auth.Principal
import io.nais.security.oauth2.config.TokenIssuerConfig
import io.nais.security.oauth2.token.verifyJwt
import mu.KotlinLogging

private val log = KotlinLogging.logger {}

data class ClientAuthenticationPrincipal(val oauth2Client: OAuth2Client, val clientAuthenticationMethod: ClientAuthenticationMethod) : Principal

data class OAuth2Client(val clientId: String, val jwkSet: JWKSet)

class ClientRegistry(
    private val tokenIssuerConfig: TokenIssuerConfig,
    private val clients: List<OAuth2Client>
) {

    fun authenticate(credential: Credential): ClientAuthenticationPrincipal? =
        when (credential) {
            is ClientAssertionCredential -> authenticate(credential)
            else -> null
        }

    private fun authenticate(credential: ClientAssertionCredential): ClientAuthenticationPrincipal? {
        log.debug("authenticating credential with client_authentication_method=${credential.clientAuthenticationMethod}")
        // add val for enableClientAssertionReuse -> unique jti?
        val oAuth2Client: OAuth2Client? = findClient(credential.clientId)
        return when {
            oAuth2Client != null -> {
                try {
                    verifyJwt(credential.signedJWT, claimsVerifierForClientIssuedToken(oAuth2Client), oAuth2Client.jwkSet)
                    ClientAuthenticationPrincipal(oAuth2Client, credential.clientAuthenticationMethod)
                } catch (e: Exception) {
                    null
                }
            }
            else -> null
        }
    }

    private fun findClient(clientId: String): OAuth2Client? = clients.asSequence().find { it.clientId == clientId }

    /**
     * Jwt Bearer token for client authentication: https://tools.ietf.org/html/draft-ietf-oauth-jwt-bearer-12
     * Threats: https://tools.ietf.org/html/draft-ietf-oauth-assertions-18#section-8.2
     *
     * Consider using jti and iat/exp in token to protect against replay attacks
     */
    private fun claimsVerifierForClientIssuedToken(oAuth2Client: OAuth2Client) =
        DefaultJWTClaimsVerifier<SecurityContext?>(
            JWTClaimsSet.Builder()
                .issuer(oAuth2Client.clientId)
                .subject(oAuth2Client.clientId)
                .audience(tokenIssuerConfig.wellKnown.tokenEndpoint)
                .build(),
            HashSet(listOf("sub", "iss", "aud", "iat", "exp", "jti"))
        )
}
