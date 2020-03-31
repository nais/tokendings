package io.nais.security.oauth2.jwt

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.time.Instant
import java.util.Date
import java.util.UUID

// TODO support more keys - i.e for rotating
class JwtTokenIssuer(
    private val issuerUrl: String,
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
                .build()
        )
    }

    private fun createSignedJWT(claimsSet: JWTClaimsSet): SignedJWT =
        SignedJWT(
            JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(rsaKey.keyID)
                .type(JOSEObjectType.JWT).build(),
            claimsSet
        ).apply {
            sign(RSASSASigner(rsaKey.toPrivateKey()))
        }

    companion object {
        private fun generateJWKSet(keyId: String, keySize: Int): JWKSet =
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
