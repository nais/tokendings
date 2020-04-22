package io.nais.security.oauth2.token

import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
import io.nais.security.oauth2.metrics.Metrics
import io.nais.security.oauth2.utils.decrypt
import io.nais.security.oauth2.utils.encrypt
import io.nais.security.oauth2.utils.withTimer
import kotliquery.Row
import kotliquery.queryOf
import kotliquery.sessionOf
import kotliquery.using
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.UUID
import javax.crypto.SecretKey
import javax.sql.DataSource

// TODO: encrypt storage of keys
internal class TokenIssuerKeyStore(
    private val dataSource: DataSource,
    private val keySize: Int,
    private val encryptionKey: SecretKey
) {

    companion object {
        private const val TABLE_NAME = "token_issuer_keys"
        private const val PRIMARY_KEY = "kid"
    }

    fun insertNewKeyPair(): RSAKey {
        val rsaKey = generateRSAKey(keySize)
        val encryptedRsaKey = encryptJwk(rsaKey)
        withTimer(Metrics.dbTimer.labels("insertNewKeyPair")) {
            using(sessionOf(dataSource)) { session ->
                session.run(
                    queryOf(
                        """INSERT INTO $TABLE_NAME(kid, jwk) values (?,?)""".trimMargin(), rsaKey.keyID, encryptedRsaKey
                    ).asUpdate
                )
            }
        }
        return rsaKey
    }

    fun findKeyPair(kid: String) =
        withTimer(Metrics.dbTimer.labels("findKeyPair")) {
            using(sessionOf(dataSource)) { session ->
                session.run(
                    queryOf(
                        """SELECT * FROM $TABLE_NAME WHERE kid=?""", kid
                    ).map {
                        decryptAndParseJwk(it)
                    }.asSingle
                )
            }
        }

    fun latestKeyPair(): JWK? =
        withTimer(Metrics.dbTimer.labels("latestKeyPair")) {
            using(sessionOf(dataSource)) { session ->
                session.run(
                    queryOf(
                        """SELECT DISTINCT ON (kid) kid, jwk, created FROM $TABLE_NAME ORDER BY kid, created ASC;"""
                    ).map {
                        decryptAndParseJwk(it)
                    }.asSingle
                )
            }
        }

    private fun encryptJwk(jwk: JWK): String =
        jwk.toJSONString().encrypt(encryptionKey)

    private fun decryptAndParseJwk(row: Row): JWK =
        JWK.parse(row.string("jwk").decrypt(encryptionKey))

    private fun generateRSAKey(keySize: Int): RSAKey =
        KeyPairGenerator.getInstance("RSA").apply { initialize(keySize) }.generateKeyPair()
            .let {
                RSAKey.Builder(it.public as RSAPublicKey)
                    .privateKey(it.private as RSAPrivateKey)
                    .keyID(UUID.randomUUID().toString())
                    .keyUse(KeyUse.SIGNATURE)
                    .build()
            }
}
