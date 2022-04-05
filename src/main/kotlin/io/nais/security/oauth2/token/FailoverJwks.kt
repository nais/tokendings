package io.nais.security.oauth2.token

import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKSelector
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jose.util.ResourceRetriever
import java.net.URL

class FailoverJwks(
    jwksetURL: URL,
    resourceRetriever: ResourceRetriever
) : JWKSource<SecurityContext?> {

    private val jwkSet: JWKSet = resourceRetriever.retrieveResource(jwksetURL).let {
        JWKSet.parse(it.content)
    }

    override fun get(jwkSelector: JWKSelector?, context: SecurityContext?): MutableList<JWK> {
        return jwkSelector?.select(jwkSet) ?: mutableListOf()
    }
}
