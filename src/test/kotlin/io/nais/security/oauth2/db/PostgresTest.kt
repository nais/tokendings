package io.nais.security.oauth2.db

import io.nais.security.oauth2.config.migrate
import io.nais.security.oauth2.mock.DataSource
import io.nais.security.oauth2.mock.withCleanDb
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals

internal class PostgresTest {
    @Test
    fun `Migration scripts are applied successfully`() {
        withCleanDb {
            val migrations = migrate(DataSource.instance)
            assertEquals(2, migrations?.migrationsExecuted, "Wrong number of migrations")
        }
    }

    @Test
    fun `Migration scripts are idempotent`() {
        withCleanDb {
            migrate(DataSource.instance)

            val migrations = migrate(DataSource.instance)
            assertEquals(0, migrations?.migrationsExecuted, "Wrong number of migrations")
        }
    }
}
