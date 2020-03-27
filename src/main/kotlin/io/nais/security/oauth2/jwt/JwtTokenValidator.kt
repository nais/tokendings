package io.nais.security.oauth2.jwt

import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT

class JwtTokenValidator {
    // TODO validate against trusted issuers
    fun validate(token: String): JWTClaimsSet {
        return SignedJWT.parse(token).jwtClaimsSet
    }
}
