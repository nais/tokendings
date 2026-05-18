package io.nais.security.oauth2.metrics

import io.prometheus.client.CollectorRegistry
import io.prometheus.client.Counter
import io.prometheus.client.Histogram

object Metrics {
    private const val NAMESPACE = "tokendings"

    private val collectorRegistry: CollectorRegistry = CollectorRegistry.defaultRegistry

    val dbTimer: Histogram =
        Histogram
            .build("db_query_latency_histogram", "Distribution of db execution times")
            .namespace(NAMESPACE)
            .labelNames("query")
            .register(collectorRegistry)

    val oauth2ErrorCounter: Counter =
        Counter
            .build()
            .namespace(NAMESPACE)
            .name("oauth2_errors")
            .help("Number of OAuth2Exceptions")
            .labelNames("code")
            .register()

    val issuedTokensCounter: Counter =
        Counter
            .build()
            .namespace(NAMESPACE)
            .name("tokens_issued")
            .help("Number of tokens we have issued")
            .labelNames("client_id", "audience")
            .register()

    val subjectTokenAudienceMismatchCounter: Counter =
        Counter
            .build()
            .namespace(NAMESPACE)
            .name("subject_token_audience_mismatch")
            .help("Number of token exchanges where the internal subject token audience does not match the requesting client_id")
            .labelNames("client_id", "subject_token_audience")
            .register()
}
