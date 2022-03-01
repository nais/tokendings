package io.nais.security.oauth2.token

data class RetryOptions(
    val times: Int = 5,
    val initialDelay: Long = 100L,
    val maxDelay: Long = 1000L,
)
