package io.nais.security.oauth2.keystore

import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKSelector
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import io.nais.security.oauth2.config.RsaKeyStoreProperties
import io.nais.security.oauth2.utils.generateRsaKey
import mu.KotlinLogging
import org.slf4j.Logger
import java.time.Duration
import java.time.LocalDateTime

private val log: Logger = KotlinLogging.logger { }

class RsaKeyService(rsaKeyStoreProperties: RsaKeyStoreProperties): JWKSource<SecurityContext?> {
    private val rsaKeyStore: RsaKeyStore = RsaKeyStore(rsaKeyStoreProperties)
    private val rotationInterval = rsaKeyStoreProperties.rotationInterval

    fun currentSigningKey(): RSAKey {
        return rotateKeys(rotationInterval).currentKey
    }

    val publicJWKSet: JWKSet
        get() {
            val keys = rotateKeys(rotationInterval)
            val jwkList: MutableList<JWK> = ArrayList()
            jwkList.add(keys.currentKey)
            jwkList.add(keys.previousKey)
            return JWKSet(jwkList).toPublicJWKSet()
        }

    internal fun rotateKeys(rotationInterval: Duration): RsaKeys {
        val rsaKeys = rsaKeyStore.read()
        if (rsaKeys.expired(LocalDateTime.now())) {
            val newKey = generateRsaKey()
            val expiry = LocalDateTime.now().plus(rotationInterval)
            return rsaKeys.rotate(newKey, expiry).also {
                rsaKeyStore.save(it)
                log.info("RSA KEY rotated, next expiry: $expiry")
            }

        }
        log.debug("RSA KEY fetched from keystore")
        return rsaKeys
    }

    override fun get(jwkSelector: JWKSelector?, context: SecurityContext?): List<JWK> {
        return publicJWKSet.keys
    }
}
