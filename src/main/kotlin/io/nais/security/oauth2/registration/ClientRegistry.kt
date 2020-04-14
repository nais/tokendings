package io.nais.security.oauth2.registration

import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod
import io.ktor.auth.Principal
import io.nais.security.oauth2.config.ClientRegistryProperties
import io.nais.security.oauth2.model.OAuth2Client
import mu.KotlinLogging

private val log = KotlinLogging.logger {}

data class ClientAuthenticationPrincipal(val oauth2Client: OAuth2Client, val clientAuthenticationMethod: ClientAuthenticationMethod) : Principal

open class ClientRegistry(
    private val clientRegistryProperties: ClientRegistryProperties
) {
    private val clients: MutableMap<String, OAuth2Client> = mutableMapOf()

    fun findClient(clientId: String): OAuth2Client? = clients[clientId]

    fun registerClient(client: OAuth2Client): OAuth2Client {
        clients[client.clientId] = client
        return client
    }
}
