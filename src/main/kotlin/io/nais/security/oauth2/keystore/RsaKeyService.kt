package io.nais.security.oauth2.keystore

import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import io.nais.security.oauth2.config.RsaKeyStoreProperties
import io.nais.security.oauth2.utils.generateRsaKey
import mu.KotlinLogging
import org.slf4j.Logger
import java.time.Duration
import java.time.LocalDateTime

private val log: Logger = KotlinLogging.logger { }

class RsaKeyService(rsaKeyStoreProperties: RsaKeyStoreProperties) {
    private val rsaKeyStore: RsaKeyStore = RsaKeyStore(rsaKeyStoreProperties)
    private val rotationInterval = rsaKeyStoreProperties.rotationInterval

    val currentSigningKey: RSAKey
        get() {
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

    internal fun getAndRotateKeys(rotationInterval: Duration): RsaKeys {
        val rsaKeys = rsaKeyStore.read()
        if (rsaKeys.expired(LocalDateTime.now())) {
            val newKey = generateRsaKey()
            val expiry = LocalDateTime.now().plus(rotationInterval)
            rsaKeyStore.save(rsaKeys.rotate(newKey, expiry))
            log.info("RSA KEY rotated, next expiry: $expiry")
            return rsaKeyStore.read()
        }
        log.debug("RSA KEY fetched from cache")
        return rsaKeys
    }
}
