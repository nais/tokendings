package io.nais.security.oauth2.token

import com.nimbusds.jose.RemoteKeySourceException
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKSelector
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import io.ktor.client.request.get
import io.nais.security.oauth2.defaultHttpClient
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import mu.KotlinLogging
import java.net.URL

private val log = KotlinLogging.logger {}

private const val DEFAULT_RETRY_ATTEMPTS = 5

open class JwkSetFailOver(
    initialJwks: String,
    private val jwkSetUri: URL,
) : JWKSource<SecurityContext> {

    // TODO handle parse
    private var jwkSet = JWKSet.parse(initialJwks)

    private fun setJWKSet(inputJwks: String) {
        val parsedJwksSet = JWKSet.parse(inputJwks)
        this.jwkSet = parsedJwksSet
    }

    override fun get(jwkSelector: JWKSelector, context: SecurityContext?): MutableList<JWK> {
        val coroutineScope = CoroutineScope(Dispatchers.Main)

        coroutineScope.launch {
            log.info("getting jwks metadata from url=$jwkSetUri")
            var responseJwksString: String?
            withContext(Dispatchers.IO) {
                responseJwksString = retry(jwkSetUri = jwkSetUri) {
                    defaultHttpClient.get<String>(jwkSetUri)
                }
                responseJwksString?.let {
                    setJWKSet(it)
                }
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
