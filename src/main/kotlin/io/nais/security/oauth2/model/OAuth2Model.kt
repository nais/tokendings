package io.nais.security.oauth2.model

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.annotation.JsonProperty
import com.nimbusds.oauth2.sdk.ErrorObject

data class OAuth2Exception(
    val errorObject: ErrorObject? = null,
    val throwable: Throwable? = null
) :
    RuntimeException(errorObject?.toJSONObject()?.toJSONString(), throwable)

object GrantType {
    const val tokenExchangeGrant = "urn:ietf:params:oauth:grant-type:token-exchange"
}

object TokenType {
    const val tokenTypeJwt = "urn:ietf:params:oauth:token-type:jwt"
}

// actually form-url-encoded
data class OAuth2TokenExchangeRequest(
    @JsonProperty("grant_type")
    val grantType: String,
    @JsonProperty("subject_token_type")
    val subjectTokenType: String,
    @JsonProperty("subject_token")
    val subjectToken: String,
    val audience: String,
    val resource: String?,
    val scope: String?
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

data class WellKnown(
    val issuer: String,
    @JsonProperty("authorization_endpoint")
    val authorizationEndpoint: String,
    @JsonProperty("token_endpoint")
    val tokenEndpoint: String,
    @JsonProperty("jwks_uri")
    val jwksUri: String,
    @JsonProperty("grant_types_supported")
    val grantTypesSupported: List<String> = listOf("urn:ietf:params:oauth:grant-type:token-exchange"),
    @JsonProperty("token_endpoint_auth_methods_supported")
    val tokenEndpointAuthMethodsSupported: List<String> = listOf("private_key_jwt"),
    @JsonProperty("token_endpoint_auth_signing_alg_values_supported")
    val tokenEndpointAuthSigningAlgValuesSupported: List<String> = listOf("RS256"),
    @JsonProperty("subject_types_supported")
    val subjectTypesSupported: List<String> = listOf("public")
)
