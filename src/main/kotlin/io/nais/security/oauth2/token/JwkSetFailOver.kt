package io.nais.security.oauth2.token

import com.nimbusds.jose.RemoteKeySourceException
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
import java.net.URL
import java.text.ParseException

private val log = KotlinLogging.logger {}

private const val DEFAULT_RETRY_ATTEMPTS = 5

class JwkSetFailOver(
    initialJwks: String,
    private val jwkSetUri: URL,
    private val resourceRetriever: ResourceRetriever,
) : JWKSource<SecurityContext> {

    // TODO handle parse
    private var jwkSet = JWKSet.parse(initialJwks)

    private fun setJWKSet(inputJwks: JWKSet) {
        this.jwkSet = inputJwks
    }

    override fun get(jwkSelector: JWKSelector, context: SecurityContext?): MutableList<JWK> {
        val coroutineScope = CoroutineScope(Dispatchers.Main)

        try {
            coroutineScope.launch {
                log.info("getting jwks metadata from url=$jwkSetUri")
                val responseJwksString: Resource?
                withContext(Dispatchers.IO) {
                    responseJwksString = retry(jwkSetUri = jwkSetUri) {
                        resourceRetriever.retrieveResource(jwkSetUri)
                    }
                    responseJwksString?.let {
                        val parsedJwksSet = JWKSet.parse(responseJwksString.content)
                        setJWKSet(parsedJwksSet)
                        log.debug("failover jwkSet updated")
                    }
                }
            }
        } catch (t: Throwable) {
            if (t is ParseException) {
                log.error(t) { "could not parse resource content to jwksSet - ${t.message}" }
            } else {
                log.error(t) { "error when trying to get current jwks from resource: $jwkSetUri - ${t.message}" }
            }
        }

        log.debug("failover jwkSet launched")
        return jwkSelector.select(jwkSet)
    }

    private suspend fun <T> retry(
        jwkSetUri: URL,
        times: Int = DEFAULT_RETRY_ATTEMPTS,
        initialDelay: Long = 100L,
        maxDelay: Long = 1000L,
        block: suspend () -> T?
    ): T? {
        var currentDelay = initialDelay
        repeat(times - 1) { attempt ->
            try {
                return block()
            } catch (e: RemoteKeySourceException) {
                log.warn(e) {
                    "$jwkSetUri: Attempt #${attempt + 1} of $times failed - retrying in $currentDelay ms - ${e.message}"
                }
                delay(currentDelay)
                currentDelay = (currentDelay * 2.0).toLong().coerceAtMost(maxDelay)
            }
        }
        return try {
            block()
        } catch (e: RemoteKeySourceException) {
            log.error(e) { "$jwkSetUri: Final retry attempt #$times failed - ${e.message}" }
            return null
        }
    }
}
