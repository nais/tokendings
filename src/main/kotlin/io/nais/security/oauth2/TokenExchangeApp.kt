package io.nais.security.oauth2

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.databind.DeserializationFeature
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.SerializationFeature
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.nimbusds.oauth2.sdk.ErrorObject
import com.nimbusds.oauth2.sdk.OAuth2Error
import io.ktor.application.Application
import io.ktor.application.call
import io.ktor.application.install
import io.ktor.client.HttpClient
import io.ktor.client.engine.apache.Apache
import io.ktor.client.features.json.JacksonSerializer
import io.ktor.client.features.json.JsonFeature
import io.ktor.features.CallId
import io.ktor.features.CallLogging
import io.ktor.features.ContentNegotiation
import io.ktor.features.DoubleReceive
import io.ktor.features.ForwardedHeaderSupport
import io.ktor.features.StatusPages
import io.ktor.features.callIdMdc
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.jackson.JacksonConverter
import io.ktor.metrics.micrometer.MicrometerMetrics
import io.ktor.response.respond
import io.ktor.routing.Routing
import io.ktor.routing.routing
import io.ktor.server.engine.applicationEngineEnvironment
import io.ktor.server.engine.connector
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.ktor.server.netty.NettyApplicationEngine
import io.ktor.util.KtorExperimentalAPI
import io.micrometer.core.instrument.Clock
import io.micrometer.core.instrument.binder.jvm.ClassLoaderMetrics
import io.micrometer.core.instrument.binder.jvm.JvmGcMetrics
import io.micrometer.core.instrument.binder.jvm.JvmMemoryMetrics
import io.micrometer.core.instrument.binder.jvm.JvmThreadMetrics
import io.micrometer.core.instrument.binder.logging.LogbackMetrics
import io.micrometer.core.instrument.binder.system.ProcessorMetrics
import io.micrometer.prometheus.PrometheusConfig
import io.micrometer.prometheus.PrometheusMeterRegistry
import io.nais.security.oauth2.config.AppConfiguration
import io.nais.security.oauth2.config.configByProfile
import io.nais.security.oauth2.model.OAuth2Exception
import io.nais.security.oauth2.observability.observabilityRouting
import io.prometheus.client.CollectorRegistry
import mu.KotlinLogging
import org.apache.http.impl.conn.SystemDefaultRoutePlanner
import org.slf4j.event.Level
import java.net.ProxySelector
import java.util.UUID

private val log = KotlinLogging.logger { }

@KtorExperimentalAPI
fun main() {
    val config: AppConfiguration = configByProfile()
    server(config).start(wait = true)
}

@KtorExperimentalAPI
fun server(config: AppConfiguration, routing: ApiRouting = DefaultRouting(config)): NettyApplicationEngine =
    embeddedServer(Netty, applicationEngineEnvironment {
        connector {
            port = config.serverProperties.port
        }
        module {
            tokenExchangeApp(config, routing)
        }
    })

@KtorExperimentalAPI
fun Application.tokenExchangeApp(config: AppConfiguration, routing: ApiRouting) {
    install(CallId) {
        generate {
            UUID.randomUUID().toString()
        }
    }

    install(CallLogging) {
        logger = log
        level = Level.INFO
        callIdMdc("callId")
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
        register(ContentType.Application.Json, JacksonConverter(Jackson.defaultMapper))
    }

    install(StatusPages) {
        exception<Throwable> { cause ->
            log.error("received exception.", cause)
            when (cause) {
                is OAuth2Exception -> {
                    val statusCode = cause.errorObject?.httpStatusCode ?: 500
                    val errorObject: ErrorObject = cause.errorObject
                        ?: OAuth2Error.SERVER_ERROR
                    call.respond(HttpStatusCode.fromValue(statusCode), errorObject)
                }
                // TODO remove cause message when closer to finished product
                else -> call.respond(HttpStatusCode.InternalServerError, cause.message ?: "unknown internal server error")
            }
        }
    }

    install(DoubleReceive)
    install(ForwardedHeaderSupport)
    observabilityRouting()
    routing.apiRouting(this)
}

interface ApiRouting {
    fun apiRouting(application: Application): Routing
}

open class DefaultRouting(private val config: AppConfiguration) : ApiRouting {
    override fun apiRouting(application: Application): Routing =
        application.routing {
            tokenExchangeApi(config)
        }
}

internal val defaultHttpClient = HttpClient(Apache) {
    install(JsonFeature) {
        serializer = JacksonSerializer {
            configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
            setSerializationInclusion(JsonInclude.Include.NON_NULL)
        }
    }
    engine {
        customizeClient { setRoutePlanner(SystemDefaultRoutePlanner(ProxySelector.getDefault())) }
    }
}

object Jackson {
    val defaultMapper: ObjectMapper = jacksonObjectMapper()

    init {
        defaultMapper.configure(SerializationFeature.INDENT_OUTPUT, true)
    }
}
