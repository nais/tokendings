package io.nais.security.oauth2.authentication

import com.auth0.jwk.Jwk
import com.auth0.jwk.JwkProvider
import com.auth0.jwk.JwkProviderBuilder
import com.nimbusds.jose.jwk.JWKSet
import io.ktor.auth.Authentication
import io.ktor.auth.jwt.JWTPrincipal
import io.ktor.auth.jwt.jwt
import io.nais.security.oauth2.authentication.BearerTokenAuth.CLIENT_REGISTRATION_AUTH
import io.nais.security.oauth2.authentication.BearerTokenAuth.INTERNAL_BEARER_TOKEN
import io.nais.security.oauth2.config.AppConfiguration
import mu.KotlinLogging
import java.net.URL
import java.util.concurrent.TimeUnit

private val log = KotlinLogging.logger { }

object BearerTokenAuth {
    const val INTERNAL_BEARER_TOKEN = "INTERNAL_BEARER_TOKEN"
    const val CLIENT_REGISTRATION_AUTH = "CLIENT_REGISTRATION_AUTH"
}

fun Authentication.Configuration.internalBearerToken(appConfig: AppConfiguration) {
    jwt(INTERNAL_BEARER_TOKEN) {
        val jwkProvider = object : JwkProvider {
            private val jwkSet: JWKSet = appConfig.tokenIssuer.publicJwkSet()
            override fun get(keyId: String?): Jwk {
                val jwk = jwkSet.getKeyByKeyId(keyId)
                return Jwk.fromValues(jwk.toJSONObject())
            }
        }
        val issuerUrl = appConfig.authorizationServerProperties.issuerUrl
        verifier(jwkProvider, issuerUrl)
        validate { credentials ->
            try {
                log.debug("received client bearer token with audience=${credentials.payload.audience}")
                require(credentials.payload.audience.contains(appConfig.authorizationServerProperties.clientRegistrationUrl())) {
                    "required audience must match client registration url"
                }
                JWTPrincipal(credentials.payload)
            } catch (e: Throwable) {
                log.debug("error in auth.", e)
                null
            }
        }
    }
}

fun Authentication.Configuration.clientRegistrationAuth(appConfig: AppConfiguration) {
    jwt(CLIENT_REGISTRATION_AUTH) {
        val properties = appConfig.clientRegistrationAuthProperties
        val jwkProvider = JwkProviderBuilder(URL(properties.wellKnown.jwksUri))
            .cached(10, 24, TimeUnit.HOURS)
            .rateLimited(10, 1, TimeUnit.MINUTES)
            .build()
        realm = "BEARER_AUTH"
        verifier(jwkProvider, properties.wellKnown.issuer) {
            withAudience(*properties.acceptedAudience.toTypedArray())
            properties.requiredClaims.forEach {
                withClaim(it.key, it.value)
            }
        }
        validate { credentials ->
            try {
                JWTPrincipal(credentials.payload)
            } catch (e: Throwable) {
                log.debug("error in validation when authenticating.", e)
                null
            }
        }
    }
}
