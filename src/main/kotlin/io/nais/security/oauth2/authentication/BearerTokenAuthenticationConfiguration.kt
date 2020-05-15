package io.nais.security.oauth2.authentication

import com.auth0.jwk.JwkProviderBuilder
import io.ktor.auth.Authentication
import io.ktor.auth.jwt.JWTPrincipal
import io.ktor.auth.jwt.jwt
import io.nais.security.oauth2.authentication.BearerTokenAuth.CLIENT_REGISTRATION_AUTH
import io.nais.security.oauth2.config.AppConfiguration
import mu.KotlinLogging
import java.net.URL
import java.util.concurrent.TimeUnit

private val log = KotlinLogging.logger { }

object BearerTokenAuth {
    const val CLIENT_REGISTRATION_AUTH = "CLIENT_REGISTRATION_AUTH"
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
