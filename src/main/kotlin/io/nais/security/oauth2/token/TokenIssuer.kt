package io.nais.security.oauth2.token

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.oauth2.sdk.OAuth2Error
import io.nais.security.oauth2.authentication.OAuth2Client
import io.nais.security.oauth2.config.TokenIssuerConfig
import io.nais.security.oauth2.config.TokenValidatorConfig
import io.nais.security.oauth2.model.OAuth2Exception
import io.nais.security.oauth2.model.OAuth2TokenRequest
import mu.KotlinLogging
import java.net.URL
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.time.Instant
import java.util.Date
import java.util.UUID

private val log = KotlinLogging.logger { }

class TokenIssuer(tokenIssuerConfig: TokenIssuerConfig, tokenValidatorConfig: TokenValidatorConfig) {

    private val tokenProvider = JwtTokenProvider(tokenIssuerConfig.issuerUrl)
    private val tokenValidators: Map<String, TokenValidator> =
        tokenValidatorConfig.issuerToWellKnownMap.entries.associate { it.key to TokenValidator(it.key, URL(it.value.jwksUri)) }

    private val internalTokenValidator: TokenValidator = TokenValidator(tokenProvider.issuerUrl, tokenProvider.publicJwkSet())

    fun publicJwkSet(): JWKSet = tokenProvider.publicJwkSet()

    fun issueTokenFor(
        oAuth2Client: OAuth2Client,
        tokenRequest: OAuth2TokenRequest
    ): SignedJWT {
        val targetAudience: String = tokenRequest.audience
        val subjectTokenJwt = SignedJWT.parse(tokenRequest.subjectToken)!!
        val issuer: String? = subjectTokenJwt.jwtClaimsSet.issuer
        val subjectTokenClaims = validator(issuer).validate(subjectTokenJwt)
        return tokenProvider.issueTokenFor(oAuth2Client.clientId, subjectTokenClaims, targetAudience)
    }

    private fun validator(issuer: String?): TokenValidator =
        when (issuer) {
            tokenProvider.issuerUrl -> internalTokenValidator
            else -> {
                issuer?.let { tokenValidators[it] }
                    ?: throw OAuth2Exception(OAuth2Error.INVALID_REQUEST.setDescription("invalid request, validator for issuer=$issuer not found"))
            }
        }
}

// TODO support more keys - i.e for rotating
class JwtTokenProvider(
    val issuerUrl: String,
    private val tokenExpiry: Long = 60,
    keySize: Int = 2048
) {
    private val jwkSet: JWKSet
    private val rsaKey: RSAKey

    init {
        val keyId = UUID.randomUUID().toString()
        jwkSet = generateJWKSet(keyId, keySize)
        rsaKey = jwkSet.getKeyByKeyId(keyId) as RSAKey
    }

    fun publicJwkSet(): JWKSet = jwkSet.toPublicJWKSet()

    // TODO include desired scope in token without validating? so it is transparent for this service
    fun issueTokenFor(
        clientId: String,
        claimsSet: JWTClaimsSet,
        audience: String
    ): SignedJWT {
        val now = Instant.now()
        return createSignedJWT(
            JWTClaimsSet.Builder(claimsSet)
                .issuer(issuerUrl)
                .expirationTime(Date.from(now.plusSeconds(tokenExpiry)))
                .notBeforeTime(Date.from(now))
                .issueTime(Date.from(now))
                .jwtID(UUID.randomUUID().toString())
                .audience(audience)
                .claim("client_id", clientId)
                .claim("idp", claimsSet.issuer)
                .build(),
            rsaKey
        )
    }

    companion object {

        fun createSignedJWT(claimsSet: JWTClaimsSet, rsaKey: RSAKey): SignedJWT =
            SignedJWT(
                JWSHeader.Builder(JWSAlgorithm.RS256)
                    .keyID(rsaKey.keyID)
                    .type(JOSEObjectType.JWT).build(),
                claimsSet
            ).apply {
                sign(RSASSASigner(rsaKey.toPrivateKey()))
            }

        fun generateJWKSet(keyId: String, keySize: Int): JWKSet =
            JWKSet(
                createJWK(
                    keyId,
                    generateKeyPair(keySize)
                )
            )

        private fun generateKeyPair(keySize: Int): KeyPair =
            KeyPairGenerator.getInstance("RSA").apply {
                initialize(keySize)
            }.generateKeyPair()

        private fun createJWK(keyID: String, keyPair: KeyPair): RSAKey =
            RSAKey.Builder(keyPair.public as RSAPublicKey)
                .privateKey(keyPair.private as RSAPrivateKey)
                .keyID(keyID)
                .build()
    }
}
