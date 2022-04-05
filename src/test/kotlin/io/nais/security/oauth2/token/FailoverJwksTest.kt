package io.nais.security.oauth2.token

import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKMatcher
import com.nimbusds.jose.jwk.JWKSelector
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.proc.SimpleSecurityContext
import io.kotest.common.runBlocking
import io.kotest.matchers.collections.shouldContainAll
import io.ktor.client.request.get
import io.nais.security.oauth2.defaultHttpClient
import io.nais.security.oauth2.mock.withMockOAuth2Server
import io.nais.security.oauth2.model.CacheProperties
import org.junit.Test
import java.net.URL
import java.util.concurrent.TimeUnit

class FailoverJwksTest {

    private val issuerId = "yolo"

    @Test
    fun `get returns correct JWK set`() {
        withMockOAuth2Server {
            val jwksURL = this.jwksUrl(issuerId).toUrl()
            val cacheProperties = testCacheProperties(jwksURL)
            val token = this.issueToken(issuerId)

            val matcher = JWKMatcher.forJWSHeader(token.header)
            val selector = JWKSelector(matcher)
            val context = SimpleSecurityContext()

            val expected: JWKSet = runBlocking {
                JWKSet.parse(defaultHttpClient.get<String>(jwksURL))
            }

            val failoverJwks = FailoverJwks(cacheProperties.jwksURL, cacheProperties.configurableResourceRetriever)
            val actual: MutableList<JWK> = failoverJwks.get(selector, context)

            actual shouldContainAll expected.keys
        }
    }

    private fun testCacheProperties(jwksURL: URL): CacheProperties = CacheProperties(
        lifeSpan = 0,
        refreshTime = 0,
        timeUnit = TimeUnit.MINUTES,
        connectionTimeout = 1000,
        readTimeOut = 1000,
        jwksURL = jwksURL
    )
}
