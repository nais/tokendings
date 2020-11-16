package io.nais.security.oauth2.admin

import io.ktor.application.call
import io.ktor.auth.authenticate
import io.ktor.response.respond
import io.ktor.routing.Route
import io.ktor.routing.route
import io.ktor.routing.get
import io.nais.security.oauth2.registration.ClientRegistry

internal fun Route.adminApi(clientRegistry: ClientRegistry) {

    authenticate("Azure AD") {
        route("/admin") {
            route("/clients") {
                get { call.respond(clientRegistry.findAll()) }
            }
        }
    }
}
