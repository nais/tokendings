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
 * Claims verifier for federated client assertions (e.g. Kubernetes
 * ServiceAccount tokens forwarded as `client_assertion`).
 *
 * Differs from [ClientAssertionJwtClaimsVerifier] in four ways:
 * - `iss` and `sub` are not bound to a registered tokendings clientId;
 *   the caller validates them separately against the allowed-issuers
 *   whitelist and the registered [io.nais.security.oauth2.model.FederatedIdentity].
 * - `aud` is multi-valued: the configured [expectedAudience] must be
 *   contained in the `aud` claim (RFC 7523 permits multi-valued audiences).
 * - `jti` and `nbf` are not required. Kubernetes projected tokens do not
 *   include `jti`.
 * - The remaining time until `exp` must not exceed [maxLifetimeSeconds].
 *   Mirrors the self-signed path's bound; rejects assertions with
 *   excessively long lifetimes.
 */
class FederatedClientAssertionJwtClaimsVerifier<C : SecurityContext?>(
    private val expectedAudience: String,
    private val maxLifetimeSeconds: Long,
) : DefaultJWTClaimsVerifier<C>(
        // exactMatchClaims = none; iss/sub are validated by the caller
        JWTClaimsSet.Builder().build(),
        requiredClaims,
    ) {
    @Throws(BadJWTException::class)
    override fun verify(
        claimsSet: JWTClaimsSet,
        context: C,
    ) {
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
        if (expectedAudience !in aud) {
            throw BadJWTException("JWT aud claim $aud does not contain expected value '$expectedAudience'")
        }

        val sub = claimsSet.subject
        if (sub.isNullOrBlank()) {
            throw BadJWTException("JWT sub claim must be present and non-empty")
        }

        // Bound the remaining lifetime of the assertion (exp - now), mirroring the
        // self-signed client-assertion check. `exp` presence is enforced by requiredClaims.
        val exp: Date = claimsSet.expirationTime
        val remainingSeconds = (exp.time - now.time) / 1000
        if (remainingSeconds > maxLifetimeSeconds) {
            throw BadJWTException(
                "JWT exceeded max lifetime: ${remainingSeconds}s remaining, max ${maxLifetimeSeconds}s",
            )
        }
    }

    companion object {
        val requiredClaims =
            setOf(
                JWTClaimNames.AUDIENCE,
                JWTClaimNames.EXPIRATION_TIME,
                JWTClaimNames.ISSUED_AT,
                JWTClaimNames.ISSUER,
                JWTClaimNames.SUBJECT,
            )
    }
}
