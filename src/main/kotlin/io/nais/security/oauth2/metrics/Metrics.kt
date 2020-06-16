package io.nais.security.oauth2.metrics

import io.prometheus.client.CollectorRegistry
import io.prometheus.client.Counter
import io.prometheus.client.Histogram

class Metrics {
    companion object {
        const val NAMESPACE = "tokendings"

        val collectorRegistry = CollectorRegistry.defaultRegistry
        val dbTimer = Histogram.build("db_query_latency_histogram", "Distribution of db execution times")
            .namespace(NAMESPACE)
            .labelNames("query")
            .register(collectorRegistry)
        val oauth2ErrorCounter = Counter
            .build()
            .namespace(NAMESPACE)
            .name("oauth2_errors")
            .help("Number of OAuth2Exceptions")
            .labelNames("code")
            .register()
    }
}
