package io.nais.security.oauth2.model

import com.fasterxml.jackson.annotation.JsonIgnore
import com.fasterxml.jackson.core.JsonGenerator
import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.databind.DeserializationContext
import com.fasterxml.jackson.databind.SerializerProvider
import com.fasterxml.jackson.databind.annotation.JsonDeserialize
import com.fasterxml.jackson.databind.annotation.JsonSerialize
import com.fasterxml.jackson.databind.deser.std.StdDeserializer
import com.fasterxml.jackson.databind.ser.std.StdSerializer
import com.nimbusds.jose.jwk.JWKSet
import io.nais.security.oauth2.Jackson
import net.minidev.json.JSONObject

// JWKSet does not implement equals and cant be directly serialized as json
data class JsonWebKeySet(
    @JsonDeserialize(using = JWKSetDeserializer::class)
    @JsonSerialize(using = JWKSetSerializer::class)
    val jwkSet: JWKSet
) {
    @JsonIgnore
    val jsonObject = jwkSet.toJSONObject()

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as JsonWebKeySet
        if (jsonObject != other.jsonObject) return false
        return true
    }

    override fun hashCode(): Int {
        return jsonObject.hashCode()
    }
}

class JWKSetDeserializer : StdDeserializer<JWKSet>(JWKSet::class.java) {
    override fun deserialize(p: JsonParser, ctxt: DeserializationContext): JWKSet {
        return JWKSet.parse(p.readValueAs(JSONObject::class.java).toJSONString())
    }
}

class JWKSetSerializer : StdSerializer<JWKSet>(JWKSet::class.java) {
    override fun serialize(value: JWKSet, gen: JsonGenerator, provider: SerializerProvider) =
        gen.writeObject(value.toJSONObject(false))
}

data class OAuth2Client(
    val clientId: String,
    val jwks: JsonWebKeySet,
    val accessPolicyInbound: AccessPolicy = AccessPolicy(),
    val accessPolicyOutbound: AccessPolicy = AccessPolicy(),
    val allowedScopes: List<String> = emptyList(),
    val allowedGrantTypes: List<String> = emptyList()
) {
    @JsonIgnore
    val jwkSet: JWKSet = jwks.jwkSet

    companion object Mapper {
        private val reader = Jackson.defaultMapper.readerFor(OAuth2Client::class.java)
        private val writer = Jackson.defaultMapper.writerFor(OAuth2Client::class.java)
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
