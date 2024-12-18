package io.nais.security.oauth2.registration

import io.nais.security.oauth2.config.ClientRegistryProperties
import io.nais.security.oauth2.model.ClientId
import io.nais.security.oauth2.model.OAuth2Client
import mu.KotlinLogging

private val log = KotlinLogging.logger {}

open class ClientRegistryPostgres(
    clientRegistryProperties: ClientRegistryProperties
) : ClientRegistry {
    private val clientStore = ClientStore(clientRegistryProperties.dataSource)

    override fun findClient(clientId: ClientId): OAuth2Client? = clientStore.find(clientId)

    override fun findClients(clientIDs: List<String>) = clientStore.findClients(clientIDs)

    override fun registerClient(client: OAuth2Client): OAuth2Client {
        log.info("register client with clientId=${client.clientId} and keyIds=${client.jwkSet.keys.map { it.keyID }.toList()}")
        clientStore.storeClient(client)
        return client
    }

    override fun findAll(): List<OAuth2Client> = clientStore.findAll()

    override fun deleteClient(clientId: ClientId) = clientStore.delete(clientId)
}
