package io.nais.security.oauth2.token

import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKSelector
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext

open class MutibleJwkFailOver(
    private val initialJwks: JWKSet,
) : JWKSource<SecurityContext> {

    private var jwkSet = initialJwks

    fun getJWKSet(): JWKSet {
        return initialJwks
    }

    fun setJWKSet(inputJwks: JWKSet) {
        this.jwkSet = inputJwks
    }

    override fun get(jwkSelector: JWKSelector, context: SecurityContext?): MutableList<JWK> {
        return jwkSelector.select(jwkSet)
    }
}
