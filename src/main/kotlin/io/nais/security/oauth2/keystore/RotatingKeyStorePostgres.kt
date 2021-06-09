package io.nais.security.oauth2.keystore

import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKSelector
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.proc.SecurityContext
import io.nais.security.oauth2.config.KeyStoreProperties
import mu.KotlinLogging
import org.slf4j.Logger
import java.time.Duration

private val log: Logger = KotlinLogging.logger { }

class RotatingKeyStorePostgres(keyStoreProperties: KeyStoreProperties) : RotatingKeyStore {
    private val keyStore: KeyStore = KeyStore(keyStoreProperties.dataSource)
    private val rotationInterval: Duration = keyStoreProperties.rotationInterval
    private val rotatableKeys: RotatableKeys = getOrGenerateKeys()

    override fun currentSigningKey(): RSAKey {
        return getAndRotateKeysIfExpired().currentKey
    }

    override fun publicJWKSet(): JWKSet = getAndRotateKeysIfExpired().let { keys ->
        return JWKSet(listOf(keys.currentKey, keys.previousKey)).toPublicJWKSet()
    }

    override fun get(jwkSelector: JWKSelector?, context: SecurityContext?): List<JWK> {
        return publicJWKSet().keys
    }

    private fun getAndRotateKeysIfExpired(): RotatableKeys {
        log.debug("checking keys for expiry and rotating if necessary")
        return if (rotatableKeys.expired()) getOrGenerateKeys() else rotatableKeys
    }

    private fun getOrGenerateKeys(): RotatableKeys =
        with(keyStore.read() ?: generateKeysAndSave()) {
            return if (notExpired()) this else rotateKeysAndSave(this)
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
}
