package io.nais.security.oauth2.rsakeystore

import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKSet
import mu.KotlinLogging
import org.slf4j.Logger
import java.time.LocalDateTime

private val log: Logger = KotlinLogging.logger { }

class RSAKeysService(
    private val keyStore: KeyStore
) {
    private var rsaKeys: RSAKeys? = null

    private fun keys(): RSAKeys {
        if (rsaKeys == null || rsaKeys!!.expired(LocalDateTime.now())) {
            log.debug("Update local cache from rsakey storage")
            rsaKeys = keyStore.keys()
        }
        return rsaKeys!!
    }

    val currentSigningKey = keys().currentKey

    val publicJWKSet: JWKSet
        get() {
            val keys = keys()
            val jwkList: MutableList<JWK> = ArrayList()
            jwkList.add(keys.currentKey!!)
            jwkList.add(keys.previousKey!!)
            return JWKSet(jwkList).toPublicJWKSet()
        }

    // For testing, can be made more elegant?
    fun resetKeys() {
        rsaKeys = null
    }
}
