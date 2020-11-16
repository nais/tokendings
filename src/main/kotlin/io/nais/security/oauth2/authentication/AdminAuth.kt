package io.nais.security.oauth2.authentication

import com.auth0.jwk.JwkProviderBuilder
import io.ktor.auth.Authentication
import io.ktor.auth.jwt.jwt
import io.nais.security.oauth2.config.AdminApiAuthProperties
import java.net.URL
import java.util.concurrent.TimeUnit

fun Authentication.Configuration.adminAuth(config: AdminApiAuthProperties) {

    jwt("Azure AD") {
        val jwkProvider = JwkProviderBuilder(URL(config.jwksUrl))
            .cached(10, 1, TimeUnit.HOURS)
            .rateLimited(50, 1, TimeUnit.MINUTES)
            .build()

        realm = "tokendings - admin"
        verifier(jwkProvider, config.acceptedIssuer)
        validate { credential ->
            // TODO Determine how to grant access. Maybe based on aad group membership?
            null
        }
    }
}
