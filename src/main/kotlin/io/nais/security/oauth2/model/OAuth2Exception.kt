package io.nais.security.oauth2.model

import com.nimbusds.oauth2.sdk.ErrorObject

data class OAuth2Exception(
    val errorObject: ErrorObject? = null,
    val throwable: Throwable? = null
) : RuntimeException(errorObject?.toJSONObject()?.toJSONString(), throwable)
