package io.nais.security.oauth2.authentication

import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.JWTClaimNames
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.proc.BadJWTException
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier
import com.nimbusds.jwt.util.DateUtils
import com.nimbusds.openid.connect.sdk.validators.BadJWTExceptions
import java.util.Date

/**
 * Extends [com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier] with:
 * - validation of the iat ("iat") claim
 * - validation of the audience ("aud") claim:
 *   - the value MUST either be a JSON string or be a JSON array with exactly one string element
 *   - the value MUST match one of the given [acceptedAudience]
 *
 * TODO: During a grace period, this currently allows for multiple accepted audience values.
 *  To comply with RFC 7523, we should only accept a single value, and the value MUST be the issuerUrl.
 */
class ClientAssertionJwtClaimsVerifier<C : SecurityContext?>(
    private val acceptedAudience: Set<String>,
    expectedIssuer: String,
    expectedSubject: String,
) : DefaultJWTClaimsVerifier<C>(
    /* exactMatchClaims = */
    JWTClaimsSet.Builder()
        .issuer(expectedIssuer)
        .subject(expectedSubject)
        .build(),
    /* requiredClaims = */
    requiredClaims,
) {
    @Throws(BadJWTException::class)
    override fun verify(claimsSet: JWTClaimsSet, context: C) {
        super.verify(claimsSet, context)

        val iat: Date = claimsSet.issueTime ?: throw BadJWTExceptions.MISSING_IAT_CLAIM_EXCEPTION
        val now = Date()
        if (iat != now && !DateUtils.isBefore(iat, now, super.getMaxClockSkew().toLong())) {
            throw BadJWTExceptions.IAT_CLAIM_AHEAD_EXCEPTION
        }

        val aud: List<String> = claimsSet.audience
        if (aud.isEmpty()) {
            throw BadJWTExceptions.MISSING_AUD_CLAIM_EXCEPTION
        }
        if (aud.size > 1 || aud.first() !in acceptedAudience) {
            throw BadJWTException("JWT aud claim has value $aud, must be exactly one of [${acceptedAudience.joinToString()}]")
        }
    }

    companion object {
        val requiredClaims = setOf(
            JWTClaimNames.AUDIENCE,
            JWTClaimNames.EXPIRATION_TIME,
            JWTClaimNames.ISSUED_AT,
            JWTClaimNames.ISSUER,
            JWTClaimNames.JWT_ID,
            JWTClaimNames.NOT_BEFORE,
            JWTClaimNames.SUBJECT,
        )
    }
}
