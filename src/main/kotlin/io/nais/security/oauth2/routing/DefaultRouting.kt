package io.nais.security.oauth2.routing

import io.ktor.server.application.Application
import io.ktor.server.routing.Routing
import io.ktor.server.routing.routing
import io.nais.security.oauth2.config.AppConfiguration

interface ApiRouting {
    fun apiRouting(application: Application): Routing
}

open class DefaultRouting(private val config: AppConfiguration) : ApiRouting {
    override fun apiRouting(application: Application): Routing =
        application.routing {
            tokenExchangeApi(config)
            clientRegistrationApi(config)
        }
}
