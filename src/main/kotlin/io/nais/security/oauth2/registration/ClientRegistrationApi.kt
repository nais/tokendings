package io.nais.security.oauth2.registration

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
import io.ktor.application.call
import io.ktor.http.HttpStatusCode
import io.ktor.request.receive
import io.ktor.response.respond
import io.ktor.routing.Route
import io.ktor.routing.post
import io.ktor.routing.route
import io.nais.security.oauth2.config.AppConfiguration
import io.nais.security.oauth2.model.ClientId
import io.nais.security.oauth2.model.GrantType
import io.nais.security.oauth2.token.JwtTokenProvider
import io.nais.security.oauth2.token.verifyJwt
import net.minidev.json.JSONObject

internal fun Route.clientRegistrationApi(config: AppConfiguration) {

    // TODO validate parameters etc - i.e. clientid etc
    // TODO Authentication bearer token with correct audience for path
    route("/registration") {
        post("/client") {
            val request: ClientRegistrationRequest = call.receive(ClientRegistrationRequest::class)
            // TODO: this is only temporary retrieve keys from authenticated principal
            val jwkSet = JwtTokenProvider.generateJWKSet("dummy", 2048)
            val softwareStatement = request.verifySoftwareStatement(jwkSet)
            val clientRegistration = ClientRegistration(
                softwareStatement.appId,
                request.jwks,
                request.softwareStatement
            )
            // TODO: add policy etc.
            /*val oauth2Client: OAuth2Client = OAuth2Client(
                clientRegistration.clientId,
                JWKSet.parse(clientRegistration.jwks)
            )*/

            call.respond(HttpStatusCode.Created, clientRegistration)
        }
    }
}

typealias SoftwareStatementJwt = String

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
data class ClientRegistrationRequest(
    @JsonProperty("client_name")
    val clientName: String,
    val jwks: JSONObject,
    @JsonProperty("software_statement")
    val softwareStatement: SoftwareStatementJwt
) {
    @JsonProperty("grant_types")
    val grantTypes: List<String> = listOf(GrantType.TOKEN_EXCHANGE_GRANT)
    @JsonProperty("token_endpoint_auth_method")
    val tokenEndpointAuthMethod: String = "private_key_jwt"
}

data class ClientRegistration(
    @JsonProperty("client_id")
    val clientId: ClientId,
    val jwks: JSONObject,
    @JsonProperty("software_statement")
    val softwareStatement: SoftwareStatementJwt,
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
