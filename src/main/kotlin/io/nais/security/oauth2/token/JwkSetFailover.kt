package io.nais.security.oauth2.token

import com.nimbusds.jose.KeySourceException
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKSelector
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jose.util.Resource
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import mu.KotlinLogging
import java.io.IOException
import java.net.URL

private val log = KotlinLogging.logger {}

class JwkSetFailover(
    initialKeySource: String,
    private val jwkSetUri: URL,
    private val options: FailoverOptions
) : JWKSource<SecurityContext> {
    private var jwkSet = initialKeySource.toJwkSet()

    private fun setJWKSet(inputJwks: JWKSet) {
        this.jwkSet = inputJwks
    }

    fun getJwkSet(): JWKSet? {
        return this.jwkSet
    }

    @Throws(KeySourceException::class)
    override fun get(jwkSelector: JWKSelector, context: SecurityContext?): MutableList<JWK> {
        options.coroutineScope.launch { updateJwkSetResourceAsync() }
        log.info("failover jwkSet launched")
        return jwkSelector.select(getJwkSet())
    }

    suspend fun updateJwkSetResourceAsync() {
        log.info("getting jwks metadata from url=$jwkSetUri")
        val resourceResponse: Resource? = retry(jwkSetUri) {
            options.resourceRetriever.retrieveResource(jwkSetUri)
        }
        resourceResponse?.content?.toJwkSet()?.let { parsedJwkSet ->
            setJWKSet(parsedJwkSet)
            log.debug("failover jwkSet updated with kid: ${parsedJwkSet.keys.map { it.keyID.toString() }}")
        }
    }

    private suspend fun <T> retry(
        jwkSetUri: URL,
        block: suspend () -> T?
    ): T? {
        var currentDelay = options.initialDelay
        repeat(options.times - 1) { attempt ->
            try {
                return block()
            } catch (e: IOException) {
                log.warn {
                    "$jwkSetUri: Attempt #${attempt + 1} of ${options.times} failed - retrying in $currentDelay ms - ${e.message}"
                }
                delay(currentDelay)
                currentDelay = (currentDelay * 2.0).toLong().coerceAtMost(options.maxDelay)
            }
        }
        return try {
            block()
        } catch (e: IOException) {
            log.error {
                "$jwkSetUri: Final retry attempt #${options.times} failed - ${e.message}"
            }
            return null
        }
    }
}
