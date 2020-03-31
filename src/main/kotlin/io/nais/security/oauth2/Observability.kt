package io.nais.security.oauth2

import io.ktor.application.Application
import io.ktor.application.ApplicationCallPipeline
import io.ktor.application.call
import io.ktor.application.install
import io.ktor.features.callId
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.content.OutgoingContent
import io.ktor.metrics.micrometer.MicrometerMetrics
import io.ktor.request.httpMethod
import io.ktor.request.uri
import io.ktor.response.ApplicationSendPipeline
import io.ktor.response.respondText
import io.ktor.response.respondTextWriter
import io.ktor.routing.get
import io.ktor.routing.routing
import io.micrometer.core.instrument.Clock
import io.micrometer.core.instrument.binder.jvm.ClassLoaderMetrics
import io.micrometer.core.instrument.binder.jvm.JvmGcMetrics
import io.micrometer.core.instrument.binder.jvm.JvmMemoryMetrics
import io.micrometer.core.instrument.binder.jvm.JvmThreadMetrics
import io.micrometer.core.instrument.binder.kafka.KafkaConsumerMetrics
import io.micrometer.core.instrument.binder.logging.LogbackMetrics
import io.micrometer.core.instrument.binder.system.ProcessorMetrics
import io.micrometer.prometheus.PrometheusConfig
import io.micrometer.prometheus.PrometheusMeterRegistry
import io.prometheus.client.CollectorRegistry
import io.prometheus.client.Counter
import io.prometheus.client.Histogram
import io.prometheus.client.exporter.common.TextFormat
import org.slf4j.Logger

private val ignoredPathsForTracing = listOf("/metrics", "/isalive", "/isready")

internal fun Application.probesAndMetrics() {
    install(MicrometerMetrics) {
        registry = PrometheusMeterRegistry(
            PrometheusConfig.DEFAULT,
            CollectorRegistry.defaultRegistry,
            Clock.SYSTEM
        )
        meterBinders = listOf(
            ClassLoaderMetrics(),
            JvmMemoryMetrics(),
            JvmGcMetrics(),
            ProcessorMetrics(),
            JvmThreadMetrics(),
            LogbackMetrics(),
            KafkaConsumerMetrics()
        )
    }

    routing {
        get("/isalive") {
            call.respondText("ALIVE", ContentType.Text.Plain)
        }
    }

    routing {
        get("/isready") {
            call.respondText("READY", ContentType.Text.Plain)
        }
    }

    routing {
        get("/metrics") {
            val names = call.request.queryParameters.getAll("name[]")?.toSet() ?: emptySet()
            call.respondTextWriter(ContentType.parse(TextFormat.CONTENT_TYPE_004)) {
                TextFormat.write004(
                    this,
                    CollectorRegistry.defaultRegistry.filteredMetricFamilySamples(
                        names
                    )
                )
            }
        }
    }
}

internal fun Application.requestResponseTracing(logger: Logger) {
    val httpRequestCounter = Counter.build(
            "http_requests_total",
            "Counts the http requests"
        )
        .labelNames("method", "code")
        .register()

    val httpRequestDuration = Histogram.build(
            "http_request_duration_seconds",
            "Distribution of http request duration"
        )
        .register()

    intercept(ApplicationCallPipeline.Monitoring) {
        try {
            if (call.request.uri in ignoredPathsForTracing) return@intercept proceed()
            logger.info("incoming callId=${call.callId} method=${call.request.httpMethod.value} uri=${call.request.uri}")
            httpRequestDuration.startTimer().use {
                proceed()
            }
        } catch (err: Throwable) {
            logger.info("exception thrown during processing: ${err.message} callId=${call.callId} ", err)
            throw err
        }
    }

    sendPipeline.intercept(ApplicationSendPipeline.After) { message ->
        val status = call.response.status() ?: (when (message) {
            is OutgoingContent -> message.status
            is HttpStatusCode -> message
            else -> null
        } ?: HttpStatusCode.OK).also { status ->
            call.response.status(status)
        }

        if (call.request.uri in ignoredPathsForTracing) return@intercept
        logger.info("responding with status=${status.value} callId=${call.callId} ")
        httpRequestCounter.labels(call.request.httpMethod.value, "${status.value}").inc()
    }
}
