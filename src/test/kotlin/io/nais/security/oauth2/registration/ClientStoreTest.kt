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
import kotlin.system.measureTimeMillis

internal class ClientStoreTest {

    @Test
    fun `storeClient should insert record or update if already present`() {
        withMigratedDb {
            with(ClientStore(DataSource.instance)) {
                val client1 = oauth2Client("testclient")
                storeClient(client1) shouldBe 1

                // should only update the record if the data is different
                storeClient(client1) shouldBe 0

                // client1 has new data
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

    @Test
    fun findClients() {
        withMigratedDb {
            with(ClientStore(DataSource.instance)) {
                val testclient = oauth2Client("testclient")
                val testclient2 = oauth2Client("testclient2")
                storeClient(testclient)
                storeClient(testclient2)
                findClients(listOf("testclient", "testclient2")) shouldBe mapOf(
                    "testclient" to testclient,
                    "testclient2" to testclient2
                )
            }
        }
    }

    @Test
    fun testStoreClientPerformance() {
        withMigratedDb {
            with(ClientStore(DataSource.instance)) {
                val clientIds = (1..50).map { "client:$it" }
                val storeTimes = mutableListOf<Long>()

                warmUpData(clientIds)

                clientIds.forEach {
                    val elapsedTime = measureTimeMillis {
                        storeClient(oauth2Client(it))
                    }
                    storeTimes.add(elapsedTime)
                    assert(elapsedTime < 400) { "storeClient took too long: $elapsedTime ms" }
                }

                val averageStoreTime = storeTimes.average()
                println("Average storeClient time: $averageStoreTime ms")
                assert(averageStoreTime < 150) { "Average storeClient time: $averageStoreTime ms" }
            }
        }
    }

    @Test
    fun testFindClientPerformance() {
        withMigratedDb {
            with(ClientStore(DataSource.instance)) {
                val clientIds = (1..50).map { "client:$it" }
                val findTimes = mutableListOf<Long>()

                warmUpData(clientIds)

                clientIds.forEach {
                    val findClientElapsedTime = measureTimeMillis {
                        find(it)
                    }
                    findTimes.add(findClientElapsedTime)
                    assert(findClientElapsedTime < 20) { "findClient took too long: $findClientElapsedTime ms" }
                }

                val averageFindTime = findTimes.average()
                println("Average findClient time: $averageFindTime ms")
                println("Total findClient time: ${findTimes.sum()} ms")
                assert(findTimes.sum() < 100) { "Total findClient time exceeded limit: ${findTimes.sum()} ms" }
            }
        }
    }

    @Test
    fun testBulkFindClientsPerformance() {
        withMigratedDb {
            with(ClientStore(DataSource.instance)) {
                val clientIds = (1..50).map { "client:$it" }

                warmUpData(clientIds)

                val findElapsedTime = measureTimeMillis {
                    findClients(clientIds)
                }
                println("Total findClients time: $findElapsedTime ms")
                assert(findElapsedTime < 100) { "findClients took too long: $findElapsedTime ms" }
            }
        }
    }

    private fun warmUpData(clientIds: List<String>, warmUpSize: Int = 5) {
        val warmUpClients = clientIds.take(warmUpSize)
        with(ClientStore(DataSource.instance)) {
            warmUpClients.forEach {
                storeClient(oauth2Client(it))
                find(it)
            }
        }
    }

    private fun oauth2Client(clientId: ClientId) = OAuth2Client(clientId, JsonWebKeys(jwkSet()))
}
