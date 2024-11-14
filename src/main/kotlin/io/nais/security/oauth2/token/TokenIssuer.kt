package io.nais.security.oauth2.token

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.oauth2.sdk.OAuth2Error
import io.nais.security.oauth2.config.AuthorizationServerProperties
import io.nais.security.oauth2.keystore.RotatingKeyStore
import io.nais.security.oauth2.metrics.Metrics.issuedTokensCounter
import io.nais.security.oauth2.model.Claim
import io.nais.security.oauth2.model.ClaimMappings
import io.nais.security.oauth2.model.ClaimValueMapping
import io.nais.security.oauth2.model.OAuth2Client
import io.nais.security.oauth2.model.OAuth2Exception
import io.nais.security.oauth2.model.OAuth2TokenExchangeRequest
import mu.KotlinLogging
import java.text.ParseException
import java.time.Instant
import java.util.Date
import java.util.UUID

private val log = KotlinLogging.logger { }

class TokenIssuer(authorizationServerProperties: AuthorizationServerProperties) {

    private val issuerUrl: String = authorizationServerProperties.issuerUrl
    private val tokenExpiry: Long = authorizationServerProperties.tokenExpiry
    private val rotatingKeyStore: RotatingKeyStore = authorizationServerProperties.rotatingKeyStore

    private val tokenValidators: Map<String, TokenValidator> =
        authorizationServerProperties.subjectTokenIssuers.associate {
            it.issuer to TokenValidator(
                it.issuer,
                it.cacheProperties
            )
        }

    private val internalTokenValidator: TokenValidator = TokenValidator(issuerUrl, rotatingKeyStore)
    private val issuerSubjectTokenMappings: Map<String, ClaimMappings> =
        authorizationServerProperties.subjectTokenIssuers.associate {
            it.issuer to it.subjectTokenClaimMappings
        }

    fun publicJwkSet(): JWKSet = rotatingKeyStore.publicJWKSet()

    fun issueTokenFor(oAuth2Client: OAuth2Client, tokenExchangeRequest: OAuth2TokenExchangeRequest): SignedJWT {
        val targetAudience: String = tokenExchangeRequest.audience
        val subjectTokenJwt = tryOrInvalidSubjectToken {
            tokenExchangeRequest.subjectToken.toJwt()
        }
        val issuer: String? = subjectTokenJwt.jwtClaimsSet.issuer
        val subjectTokenClaims = tryOrInvalidSubjectToken {
            validator(issuer).validate(subjectTokenJwt)
        }

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
                if (!subjectTokenClaims.claims.containsKey("idp")) {
                    subjectTokenClaims.issuer?.let { claim("idp", it) }
                }
            }
            .mapSubjectTokenClaims(issuer, subjectTokenClaims)
            .build().sign(rotatingKeyStore.currentSigningKey())
            .also {
                issuedTokensCounter.labels(targetAudience).inc()
            }
    }

    private fun validator(issuer: String?): TokenValidator =
        when (issuer) {
            issuerUrl -> internalTokenValidator
            else -> {
                issuer?.let { tokenValidators[it] }
                    ?: throw OAuth2Exception(
                        OAuth2Error.INVALID_REQUEST.setDescription(
                            "invalid request, cannot validate token from issuer=$issuer"
                        )
                    )
            }
        }

    private fun JWTClaimsSet.Builder.mapSubjectTokenClaims(issuer: String?, subjectTokenClaims: JWTClaimsSet): JWTClaimsSet.Builder {
        val mappings: ClaimMappings = issuer
            ?.let { issuerSubjectTokenMappings[issuer] }
            ?.takeIf { mapping -> mapping.isNotEmpty() }
            ?: return this

        for ((claim, mapping) in mappings) {
            try {
                this.mapSubjectTokenClaim(claim, mapping, subjectTokenClaims)
            } catch (e: ParseException) {
                log.warn(e) { "could not map claim '$claim' for token with issuer=$issuer" }
                continue
            }
        }

        return this
    }

    private fun JWTClaimsSet.Builder.mapSubjectTokenClaim(
        claim: Claim,
        mapping: ClaimValueMapping,
        subjectTokenClaims: JWTClaimsSet
    ): JWTClaimsSet.Builder {
        if (!subjectTokenClaims.claims.containsKey(claim)) {
            return this
        }

        val existing: String = subjectTokenClaims.getStringClaim(claim)

        for ((from, to) in mapping) {
            if (existing == from) {
                this.claim(claim, to)
            }
        }

        return this
    }
}
