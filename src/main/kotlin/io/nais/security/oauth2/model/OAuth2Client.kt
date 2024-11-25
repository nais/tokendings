package io.nais.security.oauth2.model

import com.fasterxml.jackson.annotation.JsonIgnore
import com.fasterxml.jackson.core.JsonGenerator
import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.databind.DeserializationContext
import com.fasterxml.jackson.databind.JsonDeserializer
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.JsonSerializer
import com.fasterxml.jackson.databind.SerializerProvider
import com.fasterxml.jackson.databind.annotation.JsonDeserialize
import com.fasterxml.jackson.databind.annotation.JsonSerialize
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKSet

// JWKSet does not implement equals and cant be directly serialized as json
data class JsonWebKeys(
    @JsonSerialize(using = JWKListSerializer::class)
    @JsonDeserialize(using = JWKListDeserializer::class)
    val keys: List<JWK>
) {
    constructor(jwkSet: JWKSet) : this(jwkSet.keys)

    class JWKListSerializer : JsonSerializer<List<JWK>>() {
        override fun serialize(value: List<JWK>, gen: JsonGenerator, serializers: SerializerProvider) {
            gen.writeObject(value.map { it.toJSONObject() }.toList())
        }
    }

    class JWKListDeserializer : JsonDeserializer<List<JWK>>() {
        override fun deserialize(p: JsonParser, ctxt: DeserializationContext): List<JWK> {
            return p.readValueAsTree<JsonNode>().map { JWK.parse(it.toString()) }
        }
    }
}

data class OAuth2Client(
    val clientId: ClientId,
    val jwks: JsonWebKeys,
    val accessPolicyInbound: AccessPolicy = AccessPolicy(),
    val accessPolicyOutbound: AccessPolicy = AccessPolicy(),
    val allowedScopes: List<String> = emptyList(),
    val allowedGrantTypes: List<String> = emptyList()
) {
    @JsonIgnore
    val jwkSet: JWKSet = JWKSet(jwks.keys)

    companion object Mapper {
        private val reader = jacksonObjectMapper().readerFor(OAuth2Client::class.java)
        private val writer = jacksonObjectMapper().writerFor(OAuth2Client::class.java)
        fun toJson(oAuth2Client: OAuth2Client): String = writer.writeValueAsString(oAuth2Client)
        fun fromJson(json: String): OAuth2Client = reader.readValue(json)
    }

    fun toJson(): String = toJson(this)
}

data class AccessPolicy(
    val clients: List<String> = emptyList()
) {
    fun contains(clientId: String?): Boolean = clients.contains(clientId)
}
