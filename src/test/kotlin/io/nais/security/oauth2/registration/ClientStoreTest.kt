package io.nais.security.oauth2.registration

import io.nais.security.oauth2.config.DatabaseConfig
import io.nais.security.oauth2.config.dataSourceFrom
import io.nais.security.oauth2.mock.DataSource
import io.nais.security.oauth2.mock.withMigratedDb
import io.nais.security.oauth2.model.ClientId
import io.nais.security.oauth2.model.JsonWebKeys
import io.nais.security.oauth2.model.OAuth2Client
import io.nais.security.oauth2.token.JwtTokenProvider
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

internal class ClientStoreTest {

    @Test
    fun `storeClient should insert record or update if already present`() {
        withMigratedDb {
            with(ClientStore(DataSource.instance)) {
                val rows = storeClient(oauth2Client("testclient"))
                assertThat(rows).isEqualTo(1)
                assertThat(storeClient(oauth2Client("testclient"))).isEqualTo(1)
            }
        }
    }

    @Test
    fun delete() {
        withMigratedDb {
            with(ClientStore(DataSource.instance)) {
                storeClient(oauth2Client("testclient"))
                assertThat(find("testclient")).isNotNull
                val rows = delete("testclient")
                assertThat(rows).isEqualTo(1)
                assertThat(find("testclient")).isNull()
            }
        }
    }

    @Test
    fun find() {
        withMigratedDb {
            with(ClientStore(DataSource.instance)) {
                val testclient = oauth2Client("testclient")
                storeClient(testclient)
                val found = find("testclient")
                assertThat(found).isEqualTo(testclient)
            }
        }
    }

    private fun oauth2Client(clientId: ClientId) = OAuth2Client(clientId, jwks())

    private fun jwks() = JsonWebKeys(JwtTokenProvider.generateJWKSet("testkey", 2048))

    private fun h2DataSource() = dataSourceFrom(
        DatabaseConfig(
            "jdbc:h2:mem:test",
            "user",
            "pwd"
        )
    )
}
