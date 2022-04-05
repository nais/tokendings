package io.nais.security.oauth2.model

import com.nimbusds.jose.jwk.source.DefaultJWKSetCache
import com.nimbusds.jose.util.DefaultResourceRetriever
import io.nais.security.oauth2.token.FailoverJwks
import java.net.URL
import java.util.concurrent.TimeUnit

data class CacheProperties(
    val lifeSpan: Long,
    val refreshTime: Long,
    val timeUnit: TimeUnit,
    val jwksURL: URL,
) {
    val configurableJWKSetCache = DefaultJWKSetCache(
        this.lifeSpan,
        this.refreshTime,
        this.timeUnit
    )

    val configurableResourceRetriever = DefaultResourceRetriever()

    val failoverJwks = FailoverJwks(
        this.jwksURL,
        this.configurableResourceRetriever
    )
}
