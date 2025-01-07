package io.nais.security.oauth2.health

import io.kotest.matchers.shouldBe
import io.nais.security.oauth2.mock.DataSource
import io.nais.security.oauth2.mock.withMigratedDb
import org.junit.jupiter.api.Test

class DatabaseHealthCheckTest {
    @Test
    fun `responds ok if the database is up`() {
        withMigratedDb {
            with(DatabaseHealthCheck(DataSource.instance)) {
                ping() shouldBe "pong"
            }
        }
    }
}
