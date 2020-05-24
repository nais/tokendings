package io.nais.security.oauth2.registration

import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.nais.security.oauth2.mock.DataSource
import io.nais.security.oauth2.mock.withMigratedDb
import io.nais.security.oauth2.model.ClientId
import io.nais.security.oauth2.model.JsonWebKeys
import io.nais.security.oauth2.model.OAuth2Client
import io.nais.security.oauth2.utils.jwkSet
import org.junit.jupiter.api.Test

internal class ClientStoreTest {

    @Test
    fun `storeClient should insert record or update if already present`() {
        withMigratedDb {
            with(ClientStore(DataSource.instance)) {
                val client1 = oauth2Client("testclient")
                storeClient(client1) shouldBe 1
                val client2 = oauth2Client("testclient")
                storeClient(client2) shouldBe 1
                find("testclient") shouldBe client2
            }
        }
    }

    @Test
    fun delete() {
        withMigratedDb {
            with(ClientStore(DataSource.instance)) {
                storeClient(oauth2Client("testclient"))
                find("testclient") shouldNotBe null
                delete("testclient") shouldBe 1
                find("testclient") shouldBe null
            }
        }
    }

    @Test
    fun find() {
        withMigratedDb {
            with(ClientStore(DataSource.instance)) {
                val testclient = oauth2Client("testclient")
                storeClient(testclient)
                find("testclient") shouldBe testclient
            }
        }
    }

    private fun oauth2Client(clientId: ClientId) = OAuth2Client(clientId, JsonWebKeys(jwkSet()))
}
