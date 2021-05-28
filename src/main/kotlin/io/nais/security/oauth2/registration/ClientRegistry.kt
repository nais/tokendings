package io.nais.security.oauth2.registration

import io.nais.security.oauth2.model.ClientId
import io.nais.security.oauth2.model.OAuth2Client

interface ClientRegistry {
    fun findClient(clientId: ClientId): OAuth2Client?

    fun registerClient(client: OAuth2Client): OAuth2Client

    fun findAll(): List<OAuth2Client>

    fun deleteClient(clientId: ClientId): Int
}
