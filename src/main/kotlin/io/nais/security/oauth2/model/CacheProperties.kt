package io.nais.security.oauth2.model

import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.jwk.source.JWKSourceBuilder
import com.nimbusds.jose.jwk.source.JWKSourceBuilder.DEFAULT_HTTP_CONNECT_TIMEOUT
import com.nimbusds.jose.jwk.source.JWKSourceBuilder.DEFAULT_HTTP_READ_TIMEOUT
import com.nimbusds.jose.jwk.source.JWKSourceBuilder.DEFAULT_HTTP_SIZE_LIMIT
import com.nimbusds.jose.proc.SecurityContext
import java.net.URL
import kotlin.time.Duration

data class CacheProperties(
    val lifeSpan: Duration,
    val refreshTime: Duration,
    val jwksURL: URL,
    val connectionTimeout: Int = DEFAULT_HTTP_CONNECT_TIMEOUT,
    val readTimeOut: Int = DEFAULT_HTTP_READ_TIMEOUT,
    val sizeLimit: Int = DEFAULT_HTTP_SIZE_LIMIT
) {
    private val foreverJwkSource = JWKSourceBuilder.create<SecurityContext>(jwksURL).cacheForever().build()

    val jwkSource: JWKSource<SecurityContext> = JWKSourceBuilder.create<SecurityContext>(jwksURL)
        .cache(lifeSpan.inWholeMilliseconds, refreshTime.inWholeMilliseconds)
        .failover(foreverJwkSource)
        .rateLimited(false)
        .refreshAheadCache(lifeSpan.inWholeMilliseconds / 2, true)
        .build()
}
