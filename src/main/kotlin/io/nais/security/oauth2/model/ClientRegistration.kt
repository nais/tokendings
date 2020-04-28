package io.nais.security.oauth2.model

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.annotation.JsonProperty
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.proc.JWSVerificationKeySelector
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier
import io.nais.security.oauth2.Jackson
import io.nais.security.oauth2.token.verifyJwt

typealias SoftwareStatementJwt = String

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
data class ClientRegistrationRequest(
    @JsonProperty("client_name")
    val clientName: String,
    val jwks: JsonWebKeys,
    @JsonProperty("software_statement")
    val softwareStatement: SoftwareStatementJwt? = null,
    val scopes: List<String> = emptyList(),
    @JsonProperty("grant_types")
    val grantTypes: List<String> = listOf(GrantType.TOKEN_EXCHANGE_GRANT)
) {
    companion object Mapper {
        val writer = Jackson.defaultMapper.writerFor(ClientRegistrationRequest::class.java)
        fun toJson(clientRegistrationRequest: ClientRegistrationRequest): String = writer.writeValueAsString(clientRegistrationRequest)
    }

    fun toJson(): String = toJson(this)
}

data class ClientRegistration(
    @JsonProperty("client_id")
    val clientId: ClientId,
    val jwks: JsonWebKeys,
    @JsonProperty("software_statement")
    val softwareStatement: SoftwareStatementJwt?,
    @JsonProperty("grant_types")
    val grantTypes: List<String> = listOf(GrantType.TOKEN_EXCHANGE_GRANT),
    @JsonProperty("token_endpoint_auth_method")
    val tokenEndpointAuthMethod: String = "private_key_jwt",
    val allowedScopes: List<String> = emptyList()
)

data class SoftwareStatement(
    val appId: String,
    val accessPolicyInbound: List<String> = emptyList(),
    val accessPolicyOutbound: List<String> = emptyList()
)

fun ClientRegistrationRequest.verifySoftwareStatement(jwkSet: JWKSet): SoftwareStatement =
    verifyJwt(
        SignedJWT.parse(this.softwareStatement),
        DefaultJWTClaimsVerifier(
            JWTClaimsSet.Builder().build(),
            setOf("appId", "accessPolicyInbound", "accessPolicyOutbound")
        ),
        JWSVerificationKeySelector(JWSAlgorithm.RS256, ImmutableJWKSet(jwkSet))
    ).let {
        SoftwareStatement(
            it.getStringClaim("appId"),
            it.getStringListClaim("accessPolicyInbound"),
            it.getStringListClaim("accessPolicyOutbound")
        )
    }
