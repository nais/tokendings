package io.nais.security.oauth2.mock

import com.fasterxml.jackson.annotation.JsonProperty
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.source.RemoteJWKSet
import com.nimbusds.jose.proc.JWSVerificationKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier
import io.ktor.application.ApplicationCall
import io.ktor.application.call
import io.ktor.http.HttpStatusCode
import io.ktor.http.Parameters
import io.ktor.request.receive
import io.ktor.request.receiveParameters
import io.ktor.response.respond
import io.ktor.routing.Route
import io.ktor.routing.post
import io.ktor.routing.route
import io.nais.security.oauth2.authentication.ClientAssertionCredential.Companion.JWT_BEARER
import io.nais.security.oauth2.authentication.require
import io.nais.security.oauth2.config.AppConfiguration
import io.nais.security.oauth2.routing.expiresIn
import io.nais.security.oauth2.registration.ClientRegistrationRequest
import io.nais.security.oauth2.model.OAuth2TokenResponse
import io.nais.security.oauth2.token.TokenIssuer
import io.nais.security.oauth2.token.verifyJwt
import java.net.URL

private val jwkerJwksUrl = "http://localhost:3000/jwks"

internal fun Route.clientRegistrationApi(config: AppConfiguration) {
    val issuerUrl: String = config.authorizationServerProperties.issuerUrl
    val tokenIssuer: TokenIssuer = config.tokenIssuer
    route("/registration") {

        post("/token") {
            val allowedScope = "$issuerUrl/registration/client"
            val tokenRequest: OAuth2ClientCredentialsGrantRequest = call.receiveClientCredentialsTokenRequest(allowedScope)
            // TODO verify signature on client_assertion
            val jwt: SignedJWT = SignedJWT.parse(tokenRequest.clientAssertion)
            val clientId = jwt.jwtClaimsSet.subject
            val issuedToken = tokenIssuer.issueTokenFor(clientId, tokenRequest.scope)
            call.respond(
                OAuth2TokenResponse(
                    accessToken = issuedToken.serialize(),
                    scope = tokenRequest.scope,
                    expiresIn = issuedToken.expiresIn()
                )
            )
        }

        post("/client") {
            val clientRegistrationRequest: ClientRegistrationRequest = call.receive(ClientRegistrationRequest::class)
            val softwareStatementJwt: SignedJWT = SignedJWT.parse(clientRegistrationRequest.softwareStatement)

            val claimsVerifier = DefaultJWTClaimsVerifier<SecurityContext>(
                JWTClaimsSet.Builder().build(),
                setOf("appId", "accessPolicyInbound", "accessPolicyOutbound")
            )
            // TODO figure out the blocking call warning here, but not in TokenValidator
            // Prob better to retrieve the keys earlier on with ktor client
            val softwareStatementClaimSet = verifyJwt(
                softwareStatementJwt,
                claimsVerifier,
                JWSVerificationKeySelector(JWSAlgorithm.RS256, RemoteJWKSet(URL(jwkerJwksUrl)))
            )

            call.respond(HttpStatusCode.Created, clientRegistrationRequest)
        }
    }
}

private suspend fun ApplicationCall.receiveClientCredentialsTokenRequest(allowedScope: String): OAuth2ClientCredentialsGrantRequest {
    val formParams: Parameters = receiveParameters()
    return OAuth2ClientCredentialsGrantRequest(
        formParams.require("grant_type", "client_credentials"),
        formParams.require("scope", allowedScope),
        formParams.require("client_assertion_type", JWT_BEARER),
        formParams.require("client_assertion")
    )
}

data class OAuth2ClientCredentialsGrantRequest(
    @JsonProperty("grant_type")
    val grantType: String,
    val scope: String,
    @JsonProperty("client_assertion_type")
    val clientAssertionType: String,
    @JsonProperty("client_assertion")
    val clientAssertion: String
)
