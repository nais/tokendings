package io.nais.security.oauth2.model

data class ConfigurableJWKSetCache(
    val lifeSpan: Long,
    val refreshTime: Long
)
