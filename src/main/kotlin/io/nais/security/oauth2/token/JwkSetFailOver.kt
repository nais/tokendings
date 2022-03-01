package io.nais.security.oauth2.token

import com.nimbusds.jose.KeySourceException
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKSelector
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jose.util.Resource
import com.nimbusds.jose.util.ResourceRetriever
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import mu.KotlinLogging
import java.io.IOException
import java.net.URL

private val log = KotlinLogging.logger {}

class JwkSetFailOver(
    initialKeySource: String,
    private val jwkSetUri: URL,
    private val resourceRetriever: ResourceRetriever,
    private val retryOptions: RetryOptions
) : JWKSource<SecurityContext> {
    private var jwkSet = initialKeySource.toJwkSet()
    private val dispatcher = Dispatchers.IO

    private fun setJWKSet(inputJwks: JWKSet) {
        this.jwkSet = inputJwks
    }

    fun getJwkSet(): JWKSet? {
        return this.jwkSet
    }

    @Throws(KeySourceException::class)
    override fun get(jwkSelector: JWKSelector, context: SecurityContext?): MutableList<JWK> {
        try {
            updateJwkSetResourceAsync()
        } catch (t: Throwable) {
            val errMessage = "trying to get current jwks from resource: $jwkSetUri"
            log.error(t) { "$errMessage - ${t.message}" }
            throw KeySourceException(errMessage, t)
        }

        log.debug("failover jwkSet launched")
        return jwkSelector.select(jwkSet)
    }

    fun updateJwkSetResourceAsync() {
        CoroutineScope(dispatcher).launch {
            log.info("getting jwks metadata from url=$jwkSetUri")
            withContext(dispatcher) {
                val resourceResponse: Resource? = retry(jwkSetUri, retryOptions) {
                    resourceRetriever.retrieveResource(jwkSetUri)
                }
                resourceResponse?.content?.toJwkSet()?.let { parsedJwkSet ->
                    setJWKSet(parsedJwkSet)
                    log.debug("failover jwkSet updated with kid's: ${parsedJwkSet.keys.map { it.keyID.toString() }}")
                }
            }
        }
    }

    private suspend fun <T> retry(
        jwkSetUri: URL,
        retryOptions: RetryOptions,
        block: suspend () -> T?
    ): T? {
        var currentDelay = retryOptions.initialDelay
        repeat(retryOptions.times - 1) { attempt ->
            try {
                return block()
            } catch (e: IOException) {
                log.warn {
                    "$jwkSetUri: Attempt #${attempt + 1} of ${retryOptions.times} failed - retrying in $currentDelay ms - ${e.message}"
                }
                delay(currentDelay)
                currentDelay = (currentDelay * 2.0).toLong().coerceAtMost(retryOptions.maxDelay)
            }
        }
        return try {
            block()
        } catch (e: IOException) {
            log.error {
                "$jwkSetUri: Final retry attempt #${retryOptions.times} failed - ${e.message}"
            }
            return null
        }
    }
}
