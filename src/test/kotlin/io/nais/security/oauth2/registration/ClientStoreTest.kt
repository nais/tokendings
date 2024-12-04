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
    fun testFindClientsAndStorePerformance() {
        withMigratedDb {
            with(ClientStore(DataSource.instance)) {
                val clientIds = (1..50).map { "client:$it" }
                val storeTimes = mutableListOf<Long>()

                clientIds.forEach {
                    val elapsedTime = measureTimeMillis {
                        storeClient(oauth2Client(it))
                    }
                    // Skip the first client for average calculation, as it might be slower due to initialization
                    if (it != "client:1") {
                        storeTimes.add(elapsedTime)
                        assert(elapsedTime < 400) { "storeClient took too long: $elapsedTime ms" }
                    }
                }

                val averageStoreTime = storeTimes.average()
                println("Average storeClient time: $averageStoreTime ms")
                assert(averageStoreTime < 150) { "Average storeClient time: $averageStoreTime ms" }

                // find each client
                storeTimes.clear()
                clientIds.forEach {
                    val findClientElapsedTime = measureTimeMillis {
                        find(it)
                    }
                    storeTimes.add(findClientElapsedTime)
                    assert(findClientElapsedTime < 20) { "findClient took too long: $findClientElapsedTime ms" }
                }

                val averageFindTime = storeTimes.average()
                println("Average findClient time: $averageFindTime ms")
                println("Total findClient time: ${storeTimes.sum()} ms")
                assert(storeTimes.sum() < 100) { "Average findClient time: $storeTimes.sum() ms" }

                // bulk find
                val findElapsedTime = measureTimeMillis {
                    findClients(clientIds)
                }
                println("Total findClients time: $findElapsedTime ms")
                assert(findElapsedTime < storeTimes.sum()) { "findClients took too long: $findElapsedTime ms, expected less than ${storeTimes.sum()} ms" }
            }
        }
    }

    private fun oauth2Client(clientId: ClientId) = OAuth2Client(clientId, JsonWebKeys(jwkSet()))
}
