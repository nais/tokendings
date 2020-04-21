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
            assertEquals(1, migrations, "Wrong number of migrations")
        }
    }

    @Test
    fun `Migration scripts are idempotent`() {
        withCleanDb {
            migrate(DataSource.instance)

            val migrations = migrate(DataSource.instance)
            assertEquals(0, migrations, "Wrong number of migrations")
        }
    }

    /*@Test
    fun `JDBC url is set correctly from  config values `() {
        with(hikariConfigFrom(Configuration())) {
            assertEquals("jdbc:postgresql://localhost:5432/dp-regel-api", jdbcUrl)
        }
    }*/
}
