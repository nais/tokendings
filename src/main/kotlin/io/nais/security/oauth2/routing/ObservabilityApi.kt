package io.nais.security.oauth2.routing

import io.ktor.application.call
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode.Companion.OK
import io.ktor.response.respondText
import io.ktor.response.respondTextWriter
import io.ktor.response.respond
import io.ktor.routing.Routing
import io.ktor.routing.get
import io.ktor.routing.route
import io.nais.security.oauth2.health.HealthCheck
import io.prometheus.client.CollectorRegistry
import io.prometheus.client.exporter.common.TextFormat
import kotlinx.coroutines.withTimeout

internal fun Routing.observability(databaseHealthCheck: HealthCheck) {
    route("/internal") {
        get("/isalive") {
            call.respondText("ALIVE", ContentType.Text.Plain)
        }

        get("/isready") {
            withTimeout(5000) {
                databaseHealthCheck.ping()
                call.respond(OK)
            }
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
