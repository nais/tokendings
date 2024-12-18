package io.nais.security.oauth2.model

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.databind.ObjectWriter
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier
import com.nimbusds.oauth2.sdk.OAuth2Error
import io.nais.security.oauth2.token.verify

typealias SoftwareStatementJwt = String

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
data class ClientRegistrationRequest(
    @JsonProperty("client_name") val clientName: String,
    val jwks: JsonWebKeys,
    @JsonProperty("software_statement") val softwareStatementJwt: SoftwareStatementJwt? = null,
    val scopes: List<String> = emptyList(),
    @JsonProperty("grant_types") val grantTypes: List<String> = listOf(GrantType.TOKEN_EXCHANGE_GRANT),
) {
    companion object Mapper {
        private val writer: ObjectWriter = jacksonObjectMapper().writerFor(ClientRegistrationRequest::class.java)

        fun toJson(clientRegistrationRequest: ClientRegistrationRequest): String = writer.writeValueAsString(clientRegistrationRequest)
    }

    fun toJson(): String = toJson(this)
}

data class ClientRegistration(
    @JsonProperty("client_id") val clientId: ClientId,
    val jwks: JsonWebKeys,
    @JsonProperty("software_statement") val softwareStatement: SoftwareStatementJwt?,
    @JsonProperty("grant_types") val grantTypes: List<String> = listOf(GrantType.TOKEN_EXCHANGE_GRANT),
    @JsonProperty("token_endpoint_auth_method") val tokenEndpointAuthMethod: String = "private_key_jwt",
    val allowedScopes: List<String> = emptyList(),
)

data class SoftwareStatement(
    val appId: String,
    val accessPolicyInbound: List<String> = emptyList(),
    val accessPolicyOutbound: List<String> = emptyList(),
)

fun ClientRegistrationRequest.verifySoftwareStatement(jwkSet: JWKSet): SoftwareStatement =
    SignedJWT
        .parse(this.softwareStatementJwt)
        .verify(
            DefaultJWTClaimsVerifier(
                JWTClaimsSet.Builder().build(),
                setOf("appId", "accessPolicyInbound", "accessPolicyOutbound"),
            ),
            jwkSet,
        ).let {
            SoftwareStatement(
                it.getStringClaim("appId") ?: throw OAuth2Exception(OAuth2Error.INVALID_REQUEST.setDescription("appId cannot be null")),
                it.getStringListClaim("accessPolicyInbound") ?: emptyList(),
                it.getStringListClaim("accessPolicyOutbound") ?: emptyList(),
            )
        }
