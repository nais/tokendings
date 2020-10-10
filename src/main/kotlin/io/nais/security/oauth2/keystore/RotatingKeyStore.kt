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

class RotatingKeyStore(keyStoreProperties: KeyStoreProperties) : JWKSource<SecurityContext?> {
    private val keyStore: KeyStore = KeyStore(keyStoreProperties.dataSource)
    private val rotationInterval: Duration = keyStoreProperties.rotationInterval
    private var rotatableKeys: RotatableKeys = keyStore.read() ?: saveGeneratedRsaKeys()

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

    private fun getAndRotateKeys(rotationInterval: Duration): RotatableKeys {
        log.debug("check keys for expiry and rotate if neccessary")
        if (rotatableKeys.expired()) {
            keyStore.read()?.let { current ->
                rotatableKeys = current
                if (current.expired()) {
                    val expiry = LocalDateTime.now().plus(rotationInterval)
                    rotatableKeys = current.rotate(expiry).also {
                        keyStore.save(it)
                        log.info("Keys rotated, next expiry: $expiry")
                    }
                }
            } ?: throw RuntimeException("Could not get current keys from storage")
        }
        return rotatableKeys
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
