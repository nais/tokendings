package io.nais.security.oauth2

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.databind.DeserializationFeature
import io.ktor.application.Application
import io.ktor.application.install
import io.ktor.auth.Authentication
import io.ktor.client.HttpClient
import io.ktor.client.engine.apache.Apache
import io.ktor.client.features.json.JacksonSerializer
import io.ktor.client.features.json.JsonFeature
import io.ktor.features.CallId
import io.ktor.features.CallLogging
import io.ktor.features.ContentNegotiation
import io.ktor.features.DoubleReceive
import io.ktor.features.ForwardedHeaderSupport
import io.ktor.features.callIdMdc
import io.ktor.http.ContentType
import io.ktor.jackson.JacksonConverter
import io.ktor.metrics.micrometer.MicrometerMetrics
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
import io.micrometer.core.instrument.binder.kafka.KafkaConsumerMetrics
import io.micrometer.core.instrument.binder.logging.LogbackMetrics
import io.micrometer.core.instrument.binder.system.ProcessorMetrics
import io.micrometer.prometheus.PrometheusConfig
import io.micrometer.prometheus.PrometheusMeterRegistry
import io.nais.security.oauth2.authentication.ClientRegistry
import io.nais.security.oauth2.authentication.oauth2ClientAuth
import io.nais.security.oauth2.config.Configuration
import io.nais.security.oauth2.observability.observabilityRouting
import io.nais.security.oauth2.observability.requestResponseInterceptor
import io.prometheus.client.CollectorRegistry
import mu.KotlinLogging
import org.apache.http.impl.conn.SystemDefaultRoutePlanner
import org.slf4j.LoggerFactory
import org.slf4j.event.Level
import java.net.ProxySelector
import java.util.UUID

private val secureLog = LoggerFactory.getLogger("securelog")
private val log = KotlinLogging.logger { }

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

@KtorExperimentalAPI
fun main() {
    val config = Configuration()
    tokenExchangeApp(config, DefaultRouting(config)).start(wait = true)
}

@KtorExperimentalAPI
fun tokenExchangeApp(config: Configuration, routing: ProfileAwareRouting): NettyApplicationEngine =
    embeddedServer(Netty, applicationEngineEnvironment {
        connector {
            port = config.application.port
        }

        module {
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
            install(ContentNegotiation) {
                register(ContentType.Application.Json, JacksonConverter(Jackson.defaultMapper))
            }

            install(Authentication) {
                val clientRegistry: ClientRegistry = config.tokenIssuerConfig.clientRegistry
                oauth2ClientAuth("oauth2ClientAuth") {
                    validate { credential ->
                        clientRegistry.authenticate(credential)
                    }
                }
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
                    LogbackMetrics(),
                    KafkaConsumerMetrics()
                )
            }

            install(DoubleReceive)
            install(ForwardedHeaderSupport)

            requestResponseInterceptor(log)
            observabilityRouting()
            routing.apiRouting(this)

        }
    })

interface ProfileAwareRouting {
    fun apiRouting(application: Application): Routing
}

class DefaultRouting(private val config: Configuration): ProfileAwareRouting {
    override fun apiRouting(application: Application): Routing =
        application.routing {
            tokenExchangeApi(config)
        }
}

