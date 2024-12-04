package io.nais.security.oauth2.registration

import io.nais.security.oauth2.model.ClientId
import io.nais.security.oauth2.model.OAuth2Client
import io.opentelemetry.instrumentation.annotations.SpanAttribute
import io.opentelemetry.instrumentation.annotations.WithSpan

interface ClientRegistry {
    @WithSpan
    fun findClient(@SpanAttribute clientId: ClientId): OAuth2Client?

    fun findClients(@SpanAttribute clientIds: List<String>): Map<String, OAuth2Client>

    fun registerClient(client: OAuth2Client): OAuth2Client

    fun findAll(): List<OAuth2Client>

    fun deleteClient(clientId: ClientId): Int
}
