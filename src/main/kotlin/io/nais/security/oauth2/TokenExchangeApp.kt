package io.nais.security.oauth2

import com.fasterxml.jackson.annotation.JsonInclude.Include.NON_NULL
import com.fasterxml.jackson.core.JsonProcessingException
import com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES
import com.nimbusds.oauth2.sdk.ErrorObject
import com.nimbusds.oauth2.sdk.OAuth2Error
import io.ktor.client.HttpClient
import io.ktor.client.engine.cio.CIO
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.serialization.jackson.jackson
import io.ktor.server.application.Application
import io.ktor.server.application.ApplicationCall
import io.ktor.server.application.install
import io.ktor.server.auth.Authentication
import io.ktor.server.engine.addShutdownHook
import io.ktor.server.engine.applicationEngineEnvironment
import io.ktor.server.engine.connector
import io.ktor.server.engine.embeddedServer
import io.ktor.server.engine.stop
import io.ktor.server.metrics.micrometer.MicrometerMetrics
import io.ktor.server.netty.Netty
import io.ktor.server.netty.NettyApplicationEngine
import io.ktor.server.plugins.BadRequestException
import io.ktor.server.plugins.callid.CallId
import io.ktor.server.plugins.callid.callIdMdc
import io.ktor.server.plugins.callloging.CallLogging
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.plugins.doublereceive.DoubleReceive
import io.ktor.server.plugins.forwardedheaders.ForwardedHeaders
import io.ktor.server.plugins.statuspages.StatusPages
import io.ktor.server.request.path
import io.ktor.server.response.respond
import io.ktor.server.routing.routing
import io.micrometer.core.instrument.Clock
import io.micrometer.core.instrument.binder.jvm.ClassLoaderMetrics
import io.micrometer.core.instrument.binder.jvm.JvmGcMetrics
import io.micrometer.core.instrument.binder.jvm.JvmMemoryMetrics
import io.micrometer.core.instrument.binder.jvm.JvmThreadMetrics
import io.micrometer.core.instrument.binder.logging.LogbackMetrics
import io.micrometer.core.instrument.binder.system.ProcessorMetrics
import io.micrometer.prometheus.PrometheusConfig
import io.micrometer.prometheus.PrometheusMeterRegistry
import io.nais.security.oauth2.authentication.clientRegistrationAuth
import io.nais.security.oauth2.config.AppConfiguration
import io.nais.security.oauth2.config.configByProfile
import io.nais.security.oauth2.config.isNonProd
import io.nais.security.oauth2.metrics.Metrics
import io.nais.security.oauth2.model.OAuth2Exception
import io.nais.security.oauth2.routing.ApiRouting
import io.nais.security.oauth2.routing.DefaultRouting
import io.nais.security.oauth2.routing.observability
import io.prometheus.client.CollectorRegistry
import java.util.UUID
import mu.KotlinLogging
import org.slf4j.event.Level
import java.util.concurrent.TimeUnit.SECONDS
import kotlin.system.exitProcess

private val log = KotlinLogging.logger { }

fun main() {
    try {
        val engine = server()
        engine.addShutdownHook {
            engine.stop(3, 5, SECONDS)
        }
        engine.start(wait = true)
    } catch (t: Throwable) {
        log.error("received unexpected exception when starting app. message: ${t.message}", t)
        exitProcess(1)
    }
}

fun server(): NettyApplicationEngine =
    embeddedServer(
        Netty,
        applicationEngineEnvironment {
            val config = configByProfile()
            connector {
                port = config.serverProperties.port
            }
            module {
                tokenExchangeApp(config, DefaultRouting(config))
            }
        }
    )

fun Application.tokenExchangeApp(config: AppConfiguration, routing: ApiRouting) {
    install(CallId) {
        header(HttpHeaders.XCorrelationId)
        generate { UUID.randomUUID().toString() }
        verify { callId: String -> callId.isNotEmpty() }
    }

    install(CallLogging) {
        logger = log
        level = Level.INFO
        callIdMdc("callId")
        filter { call ->
            !call.request.path().startsWith("/internal/isalive") &&
                !call.request.path().startsWith("/internal/isready") &&
                !call.request.path().startsWith("/internal/metrics")
        }
        disableDefaultColors()
    }

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
            LogbackMetrics()
        )
    }

    install(ContentNegotiation) {
        jackson() {
            configure(FAIL_ON_UNKNOWN_PROPERTIES, true)
            setSerializationInclusion(NON_NULL)
        }
    }

    install(StatusPages) {
        exception<Throwable> { call, cause ->
            log.error("request failed: $cause", cause)
            when (cause) {
                is OAuth2Exception -> {
                    val includeErrorDetails = config.isNonProd()
                    call.respondWithError(cause, includeErrorDetails)
                }
                is BadRequestException -> {
                    call.respond(HttpStatusCode.BadRequest, "invalid request content")
                }
                is JsonProcessingException -> {
                    call.respond(HttpStatusCode.BadRequest, "invalid request content")
                }
                else -> {
                    call.respond(HttpStatusCode.InternalServerError, "unknown internal server error")
                }
            }
        }
    }

    install(Authentication) {
        clientRegistrationAuth(config)
    }

    install(DoubleReceive)
    install(ForwardedHeaders)

    routing {
        observability(config.databaseHealthCheck)
        routing.apiRouting(this.application)
    }
}

private suspend fun ApplicationCall.respondWithError(exception: OAuth2Exception, includeErrorDetails: Boolean) {
    val errorObject = exception.toErrorObject(includeErrorDetails)
    Metrics.oauth2ErrorCounter.labels(errorObject.code).inc()
    this.respond(HttpStatusCode.fromValue(errorObject.httpStatusCode), errorObject.toJSONObject())
}

private fun OAuth2Exception.toErrorObject(includeErrorDetails: Boolean): ErrorObject {
    if (this.errorObject == null) {
        return OAuth2Error.SERVER_ERROR
    }
    return when (includeErrorDetails) {
        true -> this.errorObject
        else -> this.errorObject.toGeneric()
    }
}

private fun ErrorObject.toGeneric(): ErrorObject =
    ErrorObject(
        this.code,
        when (this.httpStatusCode) {
            in 400..499 -> "" + this.description
            else -> "unexpected error"
        },
        this.httpStatusCode,
        this.uri
    )

internal val defaultHttpClient = HttpClient(CIO) {
    install(io.ktor.client.plugins.contentnegotiation.ContentNegotiation) {
        jackson() {
            setSerializationInclusion(NON_NULL)
            configure(FAIL_ON_UNKNOWN_PROPERTIES, false)
        }
    }
}
