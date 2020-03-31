package io.nais.security.oauth2.model

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.annotation.JsonProperty

data class WellKnown(
    val issuer: String,
    @JsonProperty("authorization_endpoint")
    val authorizationEndpoint: String,
    @JsonProperty("token_endpoint")
    val tokenEndpoint: String,
    @JsonProperty("jwks_uri")
    val jwksUri: String,
    /*@JsonProperty("response_types_supported")
val responseTypesSupported: List<String> = listOf("code"),*/
    @JsonProperty("grant_types_supported")
    val grantTypesSupported: List<String> = listOf("urn:ietf:params:oauth:grant-type:token-exchange"),
    @JsonProperty("token_endpoint_auth_methods_supported")
    val tokenEndpointAuthMethodsSupported: List<String> = listOf("private_key_jwt"),
    @JsonProperty("token_endpoint_auth_signing_alg_values_supported")
    val tokenEndpointAuthSigningAlgValuesSupported: List<String> = listOf("RS256"),
    @JsonProperty("subject_types_supported")
    val subjectTypesSupported: List<String> = listOf("public")
    /* @JsonProperty("id_token_signing_alg_values_supported")
 val idTokenSigningAlgValuesSupported: List<String> = listOf("RS256")*/
)

@JsonInclude(JsonInclude.Include.NON_NULL)
data class OAuth2TokenResponse(
    @JsonProperty("access_token")
    val accessToken: String,
    @JsonProperty("issued_token_type")
    val issuedTokenType: String = "urn:ietf:params:oauth:token-type:access_token",
    @JsonProperty("token_type")
    val tokenType: String = "Bearer",
    @JsonProperty("expires_in")
    val expiresIn: Int = 0,
    @JsonProperty("scope")
    val scope: String? = null,
    @JsonProperty("refresh_token")
    val refreshToken: String? = null
)
