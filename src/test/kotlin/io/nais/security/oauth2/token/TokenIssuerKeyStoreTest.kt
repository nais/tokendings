package io.nais.security.oauth2.token

import com.nimbusds.jose.jwk.JWK
import io.kotlintest.matchers.string.shouldContain
import io.kotlintest.shouldBe
import io.kotlintest.shouldNotBe
import io.kotlintest.shouldThrow
import io.nais.security.oauth2.mock.DataSource
import io.nais.security.oauth2.mock.withMigratedDb
import io.nais.security.oauth2.utils.generateAESKey
import kotliquery.queryOf
import kotliquery.sessionOf
import kotliquery.using
import org.junit.jupiter.api.Test
import java.text.ParseException

internal class TokenIssuerKeyStoreTest {

    @Test
    fun `new keypair should be inserted`() {
        withMigratedDb {
            with(tokenIssuerKeyStore()) {
                val rsaKey = insertNewKeyPair()
                rsaKey shouldNotBe null
            }
        }
    }

    @Test
    fun `latestKeyPair should return latest keypair as JWK`() {
        withMigratedDb {
            with(tokenIssuerKeyStore()) {
                val first = insertNewKeyPair()
                val second = insertNewKeyPair()
                val jwk = latestKeyPair()
                jwk shouldBe second
            }
        }
    }

    @Test
    fun `findKeyPair should return JWK`() {
        withMigratedDb {
            with(tokenIssuerKeyStore()) {
                val keyToFind = insertNewKeyPair()
                val jwk = findKeyPair(keyToFind.keyID)
                jwk shouldBe keyToFind
            }
        }
    }

    @Test
    fun `verify jwk column is encrypted`() {
        withMigratedDb {
            with(tokenIssuerKeyStore()) {
                val keyToFind = insertNewKeyPair()
                val encryptedContent = using(sessionOf(DataSource.instance)) { session ->
                    session.run(
                        queryOf(
                            """SELECT * FROM token_issuer_keys WHERE kid=?""", keyToFind.keyID
                        ).map {
                            it.string("jwk")
                        }.asSingle
                    )
                }
                val exception = shouldThrow<ParseException> {
                    JWK.parse(encryptedContent)
                }
                exception.message shouldContain "Invalid JSON"
            }
        }
    }

    private fun tokenIssuerKeyStore() = TokenIssuerKeyStore(DataSource.instance, 2048, generateAESKey())
}
