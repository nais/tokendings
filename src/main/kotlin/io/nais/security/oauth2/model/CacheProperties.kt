package io.nais.security.oauth2.model

import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.jwk.source.JWKSourceBuilder
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jose.util.DefaultResourceRetriever
import java.net.URL
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.DurationUnit

data class CacheProperties(
    val jwksURL: URL,
    val timeToLive: Duration,
    val connectionTimeout: Duration = JWKSourceBuilder.DEFAULT_HTTP_CONNECT_TIMEOUT.milliseconds,
    val readTimeout: Duration = JWKSourceBuilder.DEFAULT_HTTP_READ_TIMEOUT.milliseconds,
    val refreshAheadTime: Duration = JWKSourceBuilder.DEFAULT_REFRESH_AHEAD_TIME.milliseconds,
    val refreshAheadScheduled: Boolean = true,
    val refreshTimeout: Duration = JWKSourceBuilder.DEFAULT_CACHE_REFRESH_TIMEOUT.milliseconds,
    val sizeLimitBytes: Int = JWKSourceBuilder.DEFAULT_HTTP_SIZE_LIMIT,
) {
    private val resourceRetriever =
        DefaultResourceRetriever(
            connectionTimeout.toInt(DurationUnit.MILLISECONDS),
            readTimeout.toInt(DurationUnit.MILLISECONDS),
            sizeLimitBytes,
        )
    val jwkSource: JWKSource<SecurityContext> =
        JWKSourceBuilder
            .create<SecurityContext>(jwksURL, resourceRetriever)
            .cache(timeToLive.inWholeMilliseconds, refreshTimeout.inWholeMilliseconds)
            .outageTolerantForever()
            .rateLimited(false)
            .refreshAheadCache(refreshAheadTime.inWholeMilliseconds, refreshAheadScheduled)
            .retrying(true)
            .build()
}
