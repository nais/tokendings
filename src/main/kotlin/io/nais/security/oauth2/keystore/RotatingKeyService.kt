package io.nais.security.oauth2.keystore

import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKSelector
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import io.nais.security.oauth2.config.KeyStoreProperties
import io.nais.security.oauth2.utils.generateRsaKey
import mu.KotlinLogging
import org.slf4j.Logger
import java.time.Duration
import java.time.LocalDateTime

private val log: Logger = KotlinLogging.logger { }

class RotatingKeyService(keyStoreProperties: KeyStoreProperties) : JWKSource<SecurityContext?> {
    private val keyStore: KeyStore = KeyStore(keyStoreProperties.dataSource)
    private val rotationInterval = keyStoreProperties.rotationInterval

    fun currentSigningKey(): RSAKey {
        return getAndRotateKeys(rotationInterval).currentKey
    }

    val publicJWKSet: JWKSet
        get() {
            val keys = getAndRotateKeys(rotationInterval)
            val jwkList: MutableList<JWK> = ArrayList()
            jwkList.add(keys.currentKey)
            jwkList.add(keys.previousKey)
            return JWKSet(jwkList).toPublicJWKSet()
        }

    internal fun getAndRotateKeys(rotationInterval: Duration): RotatableKeys {
        val rsaKeys = keyStore.read() ?: saveGeneratedRsaKeys()
        if (rsaKeys.expired(LocalDateTime.now())) {
            val expiry = LocalDateTime.now().plus(rotationInterval)
            return rsaKeys.rotate(expiry).also {
                keyStore.save(it)
                log.info("RSA KEY rotated, next expiry: $expiry")
            }
        }
        log.debug("RSA KEY fetched from keystore")
        return rsaKeys
    }

    override fun get(jwkSelector: JWKSelector?, context: SecurityContext?): List<JWK> {
        return publicJWKSet.keys
    }

    private fun saveGeneratedRsaKeys(): RotatableKeys =
        RotatableKeys(
            currentKey = generateRsaKey(),
            previousKey = generateRsaKey(),
            nextKey = generateRsaKey(),
            expiry = LocalDateTime.now().plus(rotationInterval)
        ).also {
            keyStore.save(it)
            log.info("RSA KEY initialised, next expiry: ${it.expiry}")
        }
}
