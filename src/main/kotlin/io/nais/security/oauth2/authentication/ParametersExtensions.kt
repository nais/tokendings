package io.nais.security.oauth2.authentication

import com.nimbusds.oauth2.sdk.OAuth2Error
import io.ktor.http.Parameters
import io.nais.security.oauth2.model.OAuth2Exception

@Throws(OAuth2Exception::class)
fun Parameters.require(name: String, requiredValue: String? = null): String =
    when {
        requiredValue != null -> {
            this[name]
                ?.takeIf { it == requiredValue }
                ?: throw OAuth2Exception(OAuth2Error.INVALID_REQUEST.setDescription("Parameter $name must be $requiredValue"))
        }
        else -> {
            this[name] ?: throw OAuth2Exception(OAuth2Error.INVALID_REQUEST.setDescription("Parameter $name missing"))
        }
    }
