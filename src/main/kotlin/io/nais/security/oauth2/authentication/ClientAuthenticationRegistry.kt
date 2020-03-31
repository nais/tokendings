package io.nais.security.oauth2.authentication

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier
import com.nimbusds.oauth2.sdk.OAuth2Error
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod
import io.ktor.auth.Credential
import io.ktor.auth.Principal
import io.nais.security.oauth2.OAuth2Exception
import io.nais.security.oauth2.config.IssuerConfig
import io.nais.security.oauth2.jwt.verifyJwt
import mu.KotlinLogging

private val log = KotlinLogging.logger {}

data class ClientAuthenticationPrincipal(val clientId: String, val clientAuthenticationMethod: ClientAuthenticationMethod) : Principal

data class OAuth2Client(val clientId: String, val jwkSet: JWKSet)

class ClientRegistry(
    private val issuerConfig: IssuerConfig,
    private val clients: List<OAuth2Client>
) {

    fun authenticate(credential: Credential): ClientAuthenticationPrincipal? =
        when (credential) {
            is ClientAuthenticationCredential -> authenticate(credential)
            else -> null
        }
    /**
     * general
     * https://tools.ietf.org/html/draft-ietf-oauth-jwt-bearer-12
     *
     * threats:
     * https://tools.ietf.org/html/draft-ietf-oauth-assertions-18#section-8.2
     *
     *  Authorization Servers and Resource Servers may use a combination
    of the Assertion ID and Issued At/Expires At attributes for replay
    protection.  Previously processed assertions may be rejected based
    on the Assertion ID.  The addition of the validity window relieves
    the authorization server from maintaining an infinite state table
    of processed Assertion IDs.
     *
     */

    fun authenticate(credential: ClientAssertionCredential): ClientAuthenticationPrincipal? {
        log.debug("authenticating credential with client_authentication_method=${credential.clientAuthenticationMethod}")
        // add val for enableClientAssertionReuse -> unique jti?
        val oAuth2Client: OAuth2Client = findClient(credential.clientId) ?: throw OAuth2Exception(OAuth2Error.INVALID_CLIENT)
        return verifyJwt(
            credential.signedJWT,
            DefaultJWTClaimsVerifier<SecurityContext?>(
                JWTClaimsSet.Builder()
                    .issuer(oAuth2Client.clientId)
                    .subject(oAuth2Client.clientId)
                    .audience(issuerConfig.wellKnown.tokenEndpoint)
                    .build(),
                HashSet(listOf("sub", "iss", "aud", "iat", "exp", "jti"))
            ),
            oAuth2Client.jwkSet
        ).let {
            ClientAuthenticationPrincipal(
                it.subject,
                credential.clientAuthenticationMethod
            )
        }
    }

    private fun findClient(clientId: String): OAuth2Client? = clients.asSequence().find { it.clientId == clientId }
}
