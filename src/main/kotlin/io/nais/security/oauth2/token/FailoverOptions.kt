package io.nais.security.oauth2.token

import com.nimbusds.jose.util.DefaultResourceRetriever

data class FailoverOptions(
    val times: Int = 5,
    val resourceRetriever: DefaultResourceRetriever,
    val initialDelay: Long = 100L,
    val maxDelay: Long = 1000L,
)
