package io.nais.security.oauth2.routing

import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode.Companion.OK
import io.ktor.server.response.respond
import io.ktor.server.response.respondText
import io.ktor.server.response.respondTextWriter
import io.ktor.server.routing.Routing
import io.ktor.server.routing.get
import io.ktor.server.routing.route
import io.nais.security.oauth2.health.HealthCheck
import io.prometheus.client.CollectorRegistry
import io.micrometer.prometheusmetrics.PrometheusMeterRegistry
import io.prometheus.client.exporter.common.TextFormat
import kotlinx.coroutines.withTimeout

private const val DB_TIMEOUT = 5000L

internal fun Routing.meta(databaseHealthCheck: HealthCheck, prometheusRegistry: PrometheusMeterRegistry) {
    route("/internal") {
        get("/isalive") {
            call.respondText("ALIVE", ContentType.Text.Plain)
        }

        get("/isready") {
            withTimeout(DB_TIMEOUT) {
                databaseHealthCheck.ping()
                call.respond(OK)
            }
        }

        get("/metrics") {
            val names = call.request.queryParameters.getAll("name[]")?.toSet() ?: emptySet()
            call.respondTextWriter(ContentType.parse(TextFormat.CONTENT_TYPE_004)) {

                prometheusRegistry.scrape()

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
