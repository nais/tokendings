package io.nais.security.oauth2.registration

import io.nais.security.oauth2.config.ClientRegistryProperties
import io.nais.security.oauth2.model.AccessPolicy
import io.nais.security.oauth2.model.ClientId
import io.nais.security.oauth2.model.OAuth2Client
import mu.KotlinLogging

private val log = KotlinLogging.logger {}

open class ClientRegistry(
    clientRegistryProperties: ClientRegistryProperties
) {
    private val clientStore = ClientStore(clientRegistryProperties.dataSource)

    fun findClient(clientId: ClientId): OAuth2Client? = clientStore.find(clientId)

    // TODO: remove manual patch
    fun registerClient(client: OAuth2Client): OAuth2Client {
        log.info("register client with clientId=${client.clientId} and keyIds=${client.jwkSet.keys.map { it.keyID }.toList()}")
        val updatePolicyIfNeccessary = handleMissingClusterInClientId(client)
        clientStore.storeClient(updatePolicyIfNeccessary)
        return client
    }

    fun findAll(): List<OAuth2Client> = clientStore.findAll()

    fun deleteClient(clientId: ClientId) = clientStore.delete(clientId)
}

fun ClientRegistry.handleMissingClusterInClientId(client: OAuth2Client): OAuth2Client {
    return when{
        client.clientId.startsWith(":") -> {
            val inboundPolicy = client.accessPolicyInbound.clients.map {
                if(it.startsWith(":")) it else ":${it.substringAfter(":")}"
            }
            OAuth2Client(
                client.clientId,
                client.jwks,
                AccessPolicy(inboundPolicy),
                client.accessPolicyOutbound,
                client.allowedScopes,
                client.allowedGrantTypes
            )
        }
        else -> client
    }
}
