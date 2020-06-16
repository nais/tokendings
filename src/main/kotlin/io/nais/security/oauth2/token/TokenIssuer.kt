package io.nais.security.oauth2.token

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.oauth2.sdk.OAuth2Error
import io.nais.security.oauth2.config.AuthorizationServerProperties
import io.nais.security.oauth2.model.OAuth2Client
import io.nais.security.oauth2.model.OAuth2Exception
import io.nais.security.oauth2.model.OAuth2TokenExchangeRequest
import mu.KotlinLogging
import java.net.URL
import java.time.Instant
import java.util.Date
import java.util.UUID

private val log = KotlinLogging.logger { }

class TokenIssuer(authorizationServerProperties: AuthorizationServerProperties) {

    private val issuerUrl: String = authorizationServerProperties.issuerUrl
    private val tokenExpiry: Long = authorizationServerProperties.tokenExpiry
    private val keyStore: KeyStore = authorizationServerProperties.keyStore

    private val tokenValidators: Map<String, TokenValidator> =
        authorizationServerProperties.subjectTokenIssuers.associate {
            it.issuer to TokenValidator(it.issuer, URL(it.wellKnown.jwksUri))
        }

    private val internalTokenValidator: TokenValidator = TokenValidator(issuerUrl, keyStore.publicJwks())

    fun publicJwkSet(): JWKSet = keyStore.publicJwks()

    fun issueTokenFor(oAuth2Client: OAuth2Client, tokenExchangeRequest: OAuth2TokenExchangeRequest): SignedJWT {
        val targetAudience: String = tokenExchangeRequest.audience
        // TODO: consider moving subjectToken validation into authnz feature
        val subjectTokenJwt = tokenExchangeRequest.subjectToken.toJwt()
        val issuer: String? = subjectTokenJwt.jwtClaimsSet.issuer
        val subjectTokenClaims = validator(issuer).validate(subjectTokenJwt)

        val now = Instant.now()
        return JWTClaimsSet.Builder(subjectTokenClaims)
            .issuer(issuerUrl)
            .expirationTime(Date.from(now.plusSeconds(tokenExpiry)))
            .notBeforeTime(Date.from(now))
            .issueTime(Date.from(now))
            .jwtID(UUID.randomUUID().toString())
            .audience(targetAudience)
            .claim("client_id", oAuth2Client.clientId)
            .apply {
                subjectTokenClaims.issuer?.let { claim("idp", it) }
            }
            .build().sign(keyStore.signingKey())
    }

    private fun validator(issuer: String?): TokenValidator =
        when (issuer) {
            issuerUrl -> internalTokenValidator
            else -> {
                issuer?.let { tokenValidators[it] }
                    ?: throw OAuth2Exception(OAuth2Error.INVALID_REQUEST.setDescription("invalid request, cannot validate token from issuer=$issuer"))
            }
        }
}
