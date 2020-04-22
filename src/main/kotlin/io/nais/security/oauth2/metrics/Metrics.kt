package io.nais.security.oauth2.metrics

import io.prometheus.client.CollectorRegistry
import io.prometheus.client.Counter
import io.prometheus.client.Histogram

class Metrics {
    companion object {
        val collectorRegistry = CollectorRegistry.defaultRegistry
        val httpTimer = Histogram.build("request_latency_histogram", "Distribution of response times")
            .labelNames("path")
            .register(collectorRegistry)
        val dbTimer = Histogram.build("db_query_latency_histogram", "Distribution of db execution times")
            .labelNames("query")
            .register(collectorRegistry)
        val somethingCounter = Counter
            .build()
            .name("something_counter")
            .help("help about something")
            .labelNames("alabel")
            .register()

        fun countSomething() = somethingCounter.labels("something_label").inc()
    }
}
