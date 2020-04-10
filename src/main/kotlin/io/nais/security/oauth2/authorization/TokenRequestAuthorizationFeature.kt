package io.nais.security.oauth2.authorization

import com.nimbusds.oauth2.sdk.OAuth2Error
import io.ktor.application.ApplicationCall
import io.ktor.application.ApplicationCallPipeline
import io.ktor.application.ApplicationFeature
import io.ktor.application.call
import io.ktor.auth.principal
import io.ktor.http.ContentType
import io.ktor.http.Parameters
import io.ktor.http.parseQueryString
import io.ktor.request.ApplicationReceivePipeline
import io.ktor.request.ApplicationReceiveRequest
import io.ktor.request.contentType
import io.ktor.util.AttributeKey
import io.ktor.util.KtorExperimentalAPI
import io.nais.security.oauth2.model.OAuth2Exception
import io.nais.security.oauth2.model.OAuth2TokenRequest
import mu.KotlinLogging
import org.slf4j.Logger

private val log: Logger = KotlinLogging.logger { }

@KtorExperimentalAPI
class TokenRequestAuthorizationFeature(configuration: Configuration) {
    private val authorizers = configuration.authorizers

    class Configuration {
        var authorizers: List<TokenRequestAuthorizer<*>> = emptyList()
    }

    companion object Feature : ApplicationFeature<ApplicationCallPipeline, Configuration, TokenRequestAuthorizationFeature> {
        override val key: AttributeKey<TokenRequestAuthorizationFeature> = AttributeKey("TokenRequestAuthorizationFeature")

        override fun install(
            pipeline: ApplicationCallPipeline,
            configure: Configuration.() -> Unit
        ): TokenRequestAuthorizationFeature {
            val configuration = Configuration().apply(configure)
            val feature = TokenRequestAuthorizationFeature(configuration)

            if (feature.authorizers.isEmpty()) {
                log.warn("Authorization feature is not configured: validators is empty")
                return feature // don't install interceptor
            }

            pipeline.receivePipeline.intercept(ApplicationReceivePipeline.After) { receive ->
                log.debug("receive pipeline with type: ${receive.type} and value: ${receive.value}")
                val parameters: Parameters? = when {
                    call.request.contentType().match(ContentType.Application.FormUrlEncoded) -> {
                        when (receive.type) {
                            Parameters::class -> receive.value as Parameters
                            String::class ->
                                if (call.request.contentType().match(ContentType.Application.FormUrlEncoded))
                                    parseQueryString(receive.value as String)
                                else
                                    null
                            else -> {
                                log.debug("could not parse ${receive.type} with ${receive.value}")
                                null
                            }
                        }
                    }
                    else -> null
                }

                if (parameters != null) {
                    val tokenRequest: OAuth2TokenRequest? = feature.authorizers.find { it.supportsGrantType(parameters["grant_type"]) }
                        ?.authorize(parameters, call.principal())
                    tokenRequest?.apply {
                        call.request.call.attributes.put(oauth2TokenRequestKey, this)
                    }
                }
                proceedWith(ApplicationReceiveRequest(receive.typeInfo, receive.value, receive.reusableValue))
            }
            return feature
        }
    }
}

val oauth2TokenRequestKey = AttributeKey<OAuth2TokenRequest>("OAuth2TokenRequest")

inline fun <reified T : OAuth2TokenRequest> ApplicationCall.receiveAuthorizedOrNull(): T? =
    request.call.attributes.getOrNull(oauth2TokenRequestKey) as? T

inline fun <reified T : OAuth2TokenRequest> ApplicationCall.receiveAuthorizedOrFail(): T =
    receiveAuthorizedOrNull() ?: throw OAuth2Exception(OAuth2Error.INVALID_REQUEST)
