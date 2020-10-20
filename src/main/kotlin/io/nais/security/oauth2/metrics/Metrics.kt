package io.nais.security.oauth2.metrics

import io.prometheus.client.CollectorRegistry
import io.prometheus.client.Counter
import io.prometheus.client.Histogram

class Metrics {
    companion object {
        private const val NAMESPACE = "tokendings"

        private val collectorRegistry: CollectorRegistry = CollectorRegistry.defaultRegistry

        val dbTimer: Histogram = Histogram.build("db_query_latency_histogram", "Distribution of db execution times")
            .namespace(NAMESPACE)
            .labelNames("query")
            .register(collectorRegistry)

        val oauth2ErrorCounter: Counter = Counter
            .build()
            .namespace(NAMESPACE)
            .name("oauth2_errors")
            .help("Number of OAuth2Exceptions")
            .labelNames("code")
            .register()

        val issuedTokensCounter: Counter = Counter
            .build()
            .namespace(NAMESPACE)
            .name("tokens_issued")
            .help("Number of tokens we have issued")
            .register()
    }
}
