package io.nais.security.oauth2.authentication

import com.auth0.jwt.exceptions.JWTVerificationException
import com.auth0.jwt.interfaces.DecodedJWT
import com.auth0.jwt.interfaces.JWTVerifier
import mu.KotlinLogging

private val log = KotlinLogging.logger { }

internal class DelegatingJWTVerifier(private val verifier: JWTVerifier) : JWTVerifier {

    override fun verify(token: String?): DecodedJWT =
        logVerificationException {
            verifier.verify(token)
        }

    override fun verify(jwt: DecodedJWT?): DecodedJWT =
        logVerificationException {
            verifier.verify(jwt)
        }

    private inline fun <reified R : Any?> logVerificationException(block: () -> R): R {
        try {
            return block()
        } catch (e: JWTVerificationException) {
            log.error("received verfication exception with message: ${e.message}", e)
            throw e
        }
    }
}
