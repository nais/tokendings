package io.nais.security.oauth2.model

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.annotation.JsonProperty
import io.nais.security.oauth2.model.GrantType.CLIENT_CREDENTIALS_GRANT
import io.nais.security.oauth2.model.GrantType.TOKEN_EXCHANGE_GRANT

typealias ClientId = String

object GrantType {
    const val TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
    const val CLIENT_CREDENTIALS_GRANT = "client_credentials"
}

object SubjectTokenType {
    const val TOKEN_TYPE_JWT = "urn:ietf:params:oauth:token-type:jwt"
}

abstract class OAuth2TokenRequest(
    @JsonProperty("grant_type")
    val grantType: String
)

// actually form-url-encoded
data class OAuth2TokenExchangeRequest(
    @JsonProperty("subject_token_type")
    val subjectTokenType: String,
    @JsonProperty("subject_token")
    val subjectToken: String,
    val audience: String,
    val resource: String? = null,
    val scope: String? = null
) : OAuth2TokenRequest(TOKEN_EXCHANGE_GRANT)

data class OAuth2ClientCredentialsTokenRequest(
    val scope: String
) : OAuth2TokenRequest(CLIENT_CREDENTIALS_GRANT)

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
