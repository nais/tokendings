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
import io.nais.security.oauth2.config.AuthorizationServerProperties
import io.nais.security.oauth2.model.OAuth2Client
import io.nais.security.oauth2.model.OAuth2Exception
import io.nais.security.oauth2.model.OAuth2TokenExchangeRequest
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

class TokenIssuer(authorizationServerProperties: AuthorizationServerProperties) {

    private val tokenProvider = JwtTokenProvider(
        authorizationServerProperties.issuerUrl,
        authorizationServerProperties.tokenExpiry,
        authorizationServerProperties.keySize
    )

    private val tokenValidators: Map<String, TokenValidator> =
        authorizationServerProperties.subjectTokenIssuers.associate {
            it.issuer to TokenValidator(it.issuer, URL(it.wellKnown.jwksUri))
        }

    private val internalTokenValidator: TokenValidator = TokenValidator(tokenProvider.issuerUrl, tokenProvider.publicJwkSet())

    fun publicJwkSet(): JWKSet = tokenProvider.publicJwkSet()

    fun issueTokenFor(oAuth2Client: OAuth2Client, tokenExchangeRequest: OAuth2TokenExchangeRequest): SignedJWT {
        val targetAudience: String = tokenExchangeRequest.audience
        val subjectTokenJwt = SignedJWT.parse(tokenExchangeRequest.subjectToken)!!
        val issuer: String? = subjectTokenJwt.jwtClaimsSet.issuer
        val subjectTokenClaims = validator(issuer).validate(subjectTokenJwt)
        return tokenProvider.issueTokenFor(oAuth2Client.clientId, subjectTokenClaims, targetAudience)
    }

    fun issueTokenFor(clientId: String, audience: String): SignedJWT {
        return tokenProvider.issueTokenFor(
            clientId,
            JWTClaimsSet.Builder().subject(clientId).build(),
            audience
        )
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
    private val tokenExpiry: Long = 300,
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

    fun issueTokenFor(clientId: String, claimsSet: JWTClaimsSet, audience: String): SignedJWT {
        val now = Instant.now()
        return JWTClaimsSet.Builder(claimsSet)
            .issuer(issuerUrl)
            .expirationTime(Date.from(now.plusSeconds(tokenExpiry)))
            .notBeforeTime(Date.from(now))
            .issueTime(Date.from(now))
            .jwtID(UUID.randomUUID().toString())
            .audience(audience)
            .claim("client_id", clientId)
            .apply {
                claimsSet.issuer?.let { claim("idp", it) }
            }
            .build().sign(rsaKey)
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

fun JWTClaimsSet.sign(rsaKey: RSAKey): SignedJWT =
    SignedJWT(
        JWSHeader.Builder(JWSAlgorithm.RS256)
            .keyID(rsaKey.keyID)
            .type(JOSEObjectType.JWT).build(),
        this
    ).apply {
        sign(RSASSASigner(rsaKey.toPrivateKey()))
    }
