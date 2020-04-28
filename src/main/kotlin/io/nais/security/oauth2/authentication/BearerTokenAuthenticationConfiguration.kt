package io.nais.security.oauth2.authentication

import com.auth0.jwk.Jwk
import com.auth0.jwk.JwkProvider
import com.nimbusds.jose.jwk.JWKSet
import io.ktor.auth.Authentication
import io.ktor.auth.jwt.JWTPrincipal
import io.ktor.auth.jwt.jwt
import io.nais.security.oauth2.authentication.BearerTokenAuth.CLIENT_BEARER_TOKEN
import io.nais.security.oauth2.config.AppConfiguration
import mu.KotlinLogging

private val log = KotlinLogging.logger { }

object BearerTokenAuth {
    const val CLIENT_BEARER_TOKEN = "CLIENT_BEARER_TOKEN"
}

fun Authentication.Configuration.clientBearerToken(appConfig: AppConfiguration) {
    jwt(CLIENT_BEARER_TOKEN) {
        val jwkProvider = jwkProviderForThisTokenIssuer(appConfig)
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

private fun jwkProviderForThisTokenIssuer(appConfig: AppConfiguration) =
    object : JwkProvider {
        private val jwkSet: JWKSet = appConfig.tokenIssuer.publicJwkSet()
        override fun get(keyId: String?): Jwk {
            val jwk = jwkSet.getKeyByKeyId(keyId)
            return Jwk.fromValues(jwk.toJSONObject())
        }
    }
