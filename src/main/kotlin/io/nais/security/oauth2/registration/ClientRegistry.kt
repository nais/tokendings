package io.nais.security.oauth2.registration

import io.nais.security.oauth2.config.ClientRegistryProperties
import io.nais.security.oauth2.model.ClientId
import io.nais.security.oauth2.model.OAuth2Client
import mu.KotlinLogging

private val log = KotlinLogging.logger {}

open class ClientRegistry(
    clientRegistryProperties: ClientRegistryProperties
) {
    // TODO fix how to inject db config
    private val clientStore = ClientStore(clientRegistryProperties.dataSource)

    // TODO: check out if suspend and coroutines makes sense with kotliquery
    fun findClient(clientId: ClientId): OAuth2Client? = clientStore.find(clientId)

    fun registerClient(client: OAuth2Client): OAuth2Client {
        log.debug("registrering client with clientId=${client.clientId}")
        clientStore.storeClient(client)
        return client
    }

    fun findAll(): List<OAuth2Client> = clientStore.findAll()

    fun deleteClient(clientId: ClientId) = clientStore.delete(clientId)
}
