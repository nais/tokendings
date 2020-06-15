package io.nais.security.oauth2.authentication

import com.auth0.jwt.exceptions.JWTVerificationException
import com.auth0.jwt.interfaces.DecodedJWT
import com.auth0.jwt.interfaces.JWTVerifier
import com.nimbusds.oauth2.sdk.OAuth2Error
import io.nais.security.oauth2.model.OAuth2Exception
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
            throw OAuth2Exception(
                OAuth2Error.INVALID_CLIENT.setDescription("token verification failed. ${e.message}")
            )
        }
    }
}
