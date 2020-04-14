package io.nais.security.oauth2.observability

import io.ktor.application.Application
import io.ktor.application.call
import io.ktor.http.ContentType
import io.ktor.response.respondText
import io.ktor.response.respondTextWriter
import io.ktor.routing.get
import io.ktor.routing.route
import io.ktor.routing.routing
import io.prometheus.client.CollectorRegistry
import io.prometheus.client.exporter.common.TextFormat

internal fun Application.observabilityRouting() {
    routing {
        route("/internal") {
            get("/isalive") {
                call.respondText("ALIVE", ContentType.Text.Plain)
            }

            get("/isready") {
                call.respondText("READY", ContentType.Text.Plain)
            }

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
}
