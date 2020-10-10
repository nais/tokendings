package io.nais.security.oauth2.keystore

import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKSelector
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import io.nais.security.oauth2.config.KeyStoreProperties
import mu.KotlinLogging
import org.slf4j.Logger
import java.time.Duration

private val log: Logger = KotlinLogging.logger { }

class RotatingKeyStore(keyStoreProperties: KeyStoreProperties) : JWKSource<SecurityContext?> {
    private val keyStore: KeyStore = KeyStore(keyStoreProperties.dataSource)
    private val rotationInterval: Duration = keyStoreProperties.rotationInterval
    private var rotatableKeys: RotatableKeys = getOrGenerateKeys()

    fun currentSigningKey(): RSAKey {
        return getAndRotateKeysIfExpired().currentKey
    }

    val publicJWKSet: JWKSet
        get() {
            val keys: RotatableKeys = getAndRotateKeysIfExpired()
            val jwkList: MutableList<JWK> = ArrayList()
            jwkList.add(keys.currentKey)
            jwkList.add(keys.previousKey)
            return JWKSet(jwkList).toPublicJWKSet()
        }

    private fun getAndRotateKeysIfExpired(): RotatableKeys {
        log.debug("checking keys for expiry and rotating if necessary")
        if (rotatableKeys.expired()) {
            rotatableKeys = getOrGenerateKeys()
        }
        return rotatableKeys
    }

    private fun getOrGenerateKeys(): RotatableKeys {
        val keys: RotatableKeys = keyStore.read() ?: generateKeysAndSave()
        if (keys.notExpired()) {
            return keys
        }
        return rotateKeysAndSave(keys)
    }

    private fun generateKeysAndSave(): RotatableKeys =
        RotatableKeys
            .generate(expiresIn = rotationInterval)
            .saveToKeyStore()
            .also { log.info("No previous key set found. Initialised new key set, next expiry: ${it.expiry}") }

    private fun rotateKeysAndSave(keys: RotatableKeys): RotatableKeys =
        keys.rotate(expiresIn = rotationInterval)
            .saveToKeyStore()
            .also { log.info("Keys rotated, next expiry: ${it.expiry}") }

    private fun RotatableKeys.saveToKeyStore(): RotatableKeys {
        // lookup keys one last time before upserting
        keyStore.read()?.let { keys ->
            if (keys.notExpired()) {
                return keys
            }
        }
        keyStore.save(this)
        return this
    }

    override fun get(jwkSelector: JWKSelector?, context: SecurityContext?): List<JWK> {
        return publicJWKSet.keys
    }
}
