package io.nais.security.oauth2.authentication

import com.auth0.jwk.Jwk
import com.auth0.jwk.JwkProvider
import com.auth0.jwk.JwkProviderBuilder
import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.interfaces.JWTVerifier
import com.nimbusds.oauth2.sdk.OAuth2Error
import io.ktor.http.auth.*
import io.ktor.server.auth.*
import io.ktor.server.auth.jwt.*
import io.nais.security.oauth2.authentication.BearerTokenAuth.CLIENT_REGISTRATION_AUTH
import io.nais.security.oauth2.authentication.BearerTokenAuth.CLIENT_REGISTRATION_SELF_SIGNED
import io.nais.security.oauth2.config.AppConfiguration
import io.nais.security.oauth2.config.ClientRegistrationAuthProperties
import io.nais.security.oauth2.config.JwkCache.BUCKET_SIZE
import io.nais.security.oauth2.config.JwkCache.CACHE_SIZE
import io.nais.security.oauth2.config.JwkCache.EXPIRES_IN
import io.nais.security.oauth2.model.OAuth2Exception
import mu.KotlinLogging
import java.net.URL
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.util.concurrent.TimeUnit

private val log = KotlinLogging.logger { }

object BearerTokenAuth {
    const val CLIENT_REGISTRATION_AUTH = "CLIENT_REGISTRATION_AUTH"
    const val CLIENT_REGISTRATION_SELF_SIGNED = "CLIENT_REGISTRATION_SELF_SIGNED"
    val ACCEPTED_ROLES_CLAIM_VALUE = listOf("access_as_application")
}

fun AuthenticationConfig.clientRegistrationJWK(appConfig: AppConfiguration) {
    jwt(CLIENT_REGISTRATION_SELF_SIGNED) {
        val properties = appConfig.clientRegistrationSelfSignedProperties
        realm = "BEARER_AUTH"
        verifier { token ->
            bearerTokenVerifier(properties, "",token)
        }

    }
}

fun AuthenticationConfig.clientRegistrationAuth(appConfig: AppConfiguration) {
    jwt(CLIENT_REGISTRATION_AUTH) {
        val properties = appConfig.clientRegistrationAuthProperties
        val jwkProvider = properties.jwkProvider
        realm = "BEARER_AUTH"
        verifier { token ->
            bearerTokenVerifier(jwkProvider, properties.issuer, token)
        }
        validate { credentials ->
            try {
                val payload = credentials.payload
                require(payload.audience.containsAll(properties.acceptedAudience)) {
                    throw OAuth2Exception(
                        OAuth2Error.INVALID_CLIENT.setDescription(
                            "audience claim does not contain accepted audience (${properties.acceptedAudience})"
                        )
                    )
                }
                require(payload.claims.containsKey("roles")) {
                    throw OAuth2Exception(
                        OAuth2Error.INVALID_CLIENT.setDescription(
                            "roles claim is not present"
                        )
                    )
                }
                val roles: List<String> = payload.getClaim("roles").asList(String::class.java)
                require(roles.containsAll(properties.acceptedRoles)) {
                    throw OAuth2Exception(
                        OAuth2Error.INVALID_CLIENT.setDescription(
                            "roles claim does not contain accepted roles (${properties.acceptedRoles}"
                        )
                    )
                }
                JWTPrincipal(credentials.payload)
            } catch (o: OAuth2Exception) {
                log.error("error in validation when authenticating.", o)
                null
            }
        }
    }
}

internal fun bearerTokenVerifier(
    jwkProvider: JwkProvider,
    issuer: String,
    token: HttpAuthHeader
): JWTVerifier {
    return try {
        val jwk = token.getBlob()?.let { jwkProvider.get(JWT.decode(it).keyId) }
            ?: throw OAuth2Exception(OAuth2Error.INVALID_REQUEST.setDescription("unable to find public key for token"))
        val algorithm = jwk.makeAlgorithm()

        DelegatingJWTVerifier(
            JWT.require(algorithm)
                .withIssuer(issuer)
                .build()
        )
    } catch (t: Throwable) {
        log.error("received exception when validating token, message: ${t.message}", t)
        throw t
    }
}

private fun HttpAuthHeader.getBlob(): String? = when {
    this is HttpAuthHeader.Single && authScheme.lowercase() in listOf("bearer") -> blob
    else -> null
}

private fun Jwk.makeAlgorithm(): Algorithm = when (algorithm) {
    "RS256" -> Algorithm.RSA256(publicKey as RSAPublicKey, null)
    "RS384" -> Algorithm.RSA384(publicKey as RSAPublicKey, null)
    "RS512" -> Algorithm.RSA512(publicKey as RSAPublicKey, null)
    "ES256" -> Algorithm.ECDSA256(publicKey as ECPublicKey, null)
    "ES384" -> Algorithm.ECDSA384(publicKey as ECPublicKey, null)
    "ES512" -> Algorithm.ECDSA512(publicKey as ECPublicKey, null)
    null -> Algorithm.RSA256(publicKey as RSAPublicKey, null)
    else -> throw IllegalArgumentException("Unsupported algorithm $algorithm")
}
