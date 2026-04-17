package io.nais.security.oauth2.authentication

import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.jwt.proc.JWTClaimsSetVerifier
import com.nimbusds.oauth2.sdk.OAuth2Error
import io.ktor.http.Parameters
import io.ktor.server.application.ApplicationCall
import io.ktor.server.request.receiveParameters
import io.nais.security.oauth2.config.FederatedClientAuthProperties
import io.nais.security.oauth2.config.FederatedIssuer
import io.nais.security.oauth2.model.ClientId
import io.nais.security.oauth2.model.OAuth2Client
import io.nais.security.oauth2.model.OAuth2Exception
import io.nais.security.oauth2.model.OAuth2TokenRequest
import io.nais.security.oauth2.token.TokenValidator
import io.nais.security.oauth2.token.expiresIn
import io.nais.security.oauth2.token.toJwt
import io.nais.security.oauth2.token.verify
import io.opentelemetry.api.trace.SpanKind
import io.opentelemetry.instrumentation.annotations.WithSpan
import mu.KotlinLogging
import org.slf4j.MDC

typealias AcceptedAudience = Set<String>

private val log = KotlinLogging.logger { }

class TokenRequestContext private constructor(
    val oauth2Client: OAuth2Client,
    val oauth2TokenRequest: OAuth2TokenRequest,
) {
    data class ClientIDs(
        val client: String,
        val target: String,
    )

    class From(
        private val parameters: Parameters,
    ) {
        @WithSpan
        fun authenticateAndAuthorize(configure: TokenRequestConfig.Configuration.(ClientIDs) -> Unit): TokenRequestContext {
            val credential = credential()
            val config =
                TokenRequestConfig(
                    TokenRequestConfig.Configuration().apply {
                        val clientIds =
                            ClientIDs(
                                client = credential.subject,
                                target = parameters.require("audience"),
                            )
                        configure(clientIds)
                    },
                )
            val client: OAuth2Client = authenticateClient(config, credential)
            MDC.put("client_id", client.clientId)
            val tokenRequest = authorizeTokenRequest(config, client)
            return TokenRequestContext(client, tokenRequest)
        }

        private fun credential(): ParsedClientAssertion {
            val clientAssertionType = parameters.require("client_assertion_type")
            if (clientAssertionType != ClientCredential.JWT_BEARER) {
                throw OAuth2Exception(OAuth2Error.INVALID_CLIENT.appendDescription(": invalid client_assertion_type"))
            }
            val signedJWT = parameters.require("client_assertion").toJwt()
            val claims = signedJWT.jwtClaimsSet
            val iss = claims?.issuer
            val sub = claims?.subject
            if (sub.isNullOrBlank()) {
                throw OAuth2Exception(OAuth2Error.INVALID_CLIENT.appendDescription(": sub must be present in assertion"))
            }
            if (iss.isNullOrBlank()) {
                throw OAuth2Exception(OAuth2Error.INVALID_CLIENT.appendDescription(": iss must be present in assertion"))
            }
            return ParsedClientAssertion(signedJWT, iss, sub)
        }

        @WithSpan
        private fun authenticateClient(
            config: TokenRequestConfig,
            credential: ParsedClientAssertion,
        ): OAuth2Client {
            // Dispatch on iss: if the assertion's iss is in the federated whitelist,
            // treat as federated; otherwise treat as self-signed (iss == sub == clientId).
            val federated = config.federatedClientAuthProperties?.allowedIssuers?.get(credential.issuer)
            return if (federated != null) {
                authenticateFederated(
                    config = config,
                    credential = ClientCredential.Federated(credential.signedJWT, credential.issuer, credential.subject),
                    federatedIssuer = federated,
                )
            } else {
                authenticateSelfSigned(
                    config = config,
                    credential = ClientCredential.SelfSigned(credential.signedJWT, credential.subject),
                )
            }
        }

        private fun authenticateSelfSigned(
            config: TokenRequestConfig,
            credential: ClientCredential.SelfSigned,
        ): OAuth2Client {
            val client =
                config.clientFinder.invoke(credential.clientId)
                    ?: throw OAuth2Exception(
                        OAuth2Error.INVALID_CLIENT.setDescription(
                            "invalid client authentication for client_id=${credential.clientId}, client not registered.",
                        ),
                    )
            val keyIds =
                client.jwkSet.keys
                    .map { it.keyID }
                    .toList()
            log.info("verify client_assertion for client_id=${client.clientId} with keyIds=$keyIds")
            credential.signedJWT.verify(
                config.claimsVerifier(client.clientId),
                client.jwkSet,
            )
            if (!credential.signedJWT.isWithinMaxLifetime(config.clientAssertionMaxLifetime)) {
                throw OAuth2Exception(
                    OAuth2Error.INVALID_CLIENT.setDescription(
                        "invalid client authentication for client_id=${credential.clientId}," +
                            " client assertion exceeded max lifetime (${config.clientAssertionMaxLifetime}s).",
                    ),
                )
            }
            return client
        }

        private fun authenticateFederated(
            config: TokenRequestConfig,
            credential: ClientCredential.Federated,
            federatedIssuer: FederatedIssuer,
        ): OAuth2Client {
            val federatedConfig =
                config.federatedClientAuthProperties
                    ?: throw OAuth2Exception(
                        OAuth2Error.INVALID_CLIENT.setDescription(
                            "federated client authentication is not enabled",
                        ),
                    )
            val expectedAudience =
                federatedConfig.audience
                    ?: throw OAuth2Exception(
                        OAuth2Error.INVALID_CLIENT.setDescription(
                            "federated client authentication is not fully configured (missing audience)",
                        ),
                    )

            log.info(
                "verify federated client_assertion iss=${credential.issuer} sub=${credential.subject} " +
                    "kid=${credential.signedJWT.header.keyID}",
            )
            val validator =
                TokenValidator(
                    issuer = federatedIssuer.issuer,
                    cacheProperties = federatedIssuer.cacheProperties,
                    extraClaimsVerifier =
                        FederatedClientAssertionJwtClaimsVerifier(
                            expectedAudience = expectedAudience,
                            maxLifetimeSeconds = federatedConfig.maxAssertionLifetimeSeconds,
                        ),
                )
            validator.validate(credential.signedJWT)

            val client =
                config.federatedClientFinder.invoke(credential.issuer, credential.subject)
                    ?: throw OAuth2Exception(
                        OAuth2Error.INVALID_CLIENT.setDescription(
                            "no client registered for federated identity iss=${credential.issuer} sub=${credential.subject}",
                        ),
                    )
            // Belt and suspenders: reject if registry returned a client whose federated identity
            // doesn't match (should not happen given the unique index).
            val registered = client.federatedIdentity
            if (registered == null || registered.issuer != credential.issuer || registered.subject != credential.subject) {
                throw OAuth2Exception(
                    OAuth2Error.INVALID_CLIENT.setDescription(
                        "registered client ${client.clientId} federated identity mismatch",
                    ),
                )
            }
            return client
        }

        @WithSpan
        private fun authorizeTokenRequest(
            config: TokenRequestConfig,
            client: OAuth2Client,
        ): OAuth2TokenRequest =
            config.authorizers
                .find { it.supportsGrantType(parameters["grant_type"]) }
                ?.authorize(parameters, client)
                ?: throw OAuth2Exception(
                    OAuth2Error.ACCESS_DENIED.setDescription(
                        "could not find authorizer for grant_type=${parameters["grant_type"]}",
                    ),
                )
    }
}

class TokenRequestConfig internal constructor(
    configuration: Configuration,
) {
    internal val clientFinder = configuration.clientFinder
    internal val federatedClientFinder = configuration.federatedClientFinder
    internal val claimsVerifier = configuration.claimsVerifier
    internal val authorizers = configuration.authorizers
    internal val clientAssertionMaxLifetime = configuration.clientAssertionMaxLifetime
    internal val federatedClientAuthProperties = configuration.federatedClientAuthProperties

    class Configuration {
        internal var clientFinder: (ClientId) -> OAuth2Client? = {
            throw NotImplementedError("clientFinder function not implemented")
        }
        internal var federatedClientFinder: (String, String) -> OAuth2Client? = { _, _ -> null }
        internal var federatedClientAuthProperties: FederatedClientAuthProperties? = null
        internal var authorizers: List<TokenRequestAuthorizer<*>> = emptyList()

        internal lateinit var acceptedAudience: AcceptedAudience
        internal var claimsVerifier: (ClientId) -> JWTClaimsSetVerifier<SecurityContext?> = { clientId ->
            ClientAssertionJwtClaimsVerifier(
                acceptedAudience = acceptedAudience,
                expectedIssuer = clientId,
                expectedSubject = clientId,
            )
        }

        internal var clientAssertionMaxLifetime: Long = CLIENT_ASSERTION_MAX_LIFETIME
    }

    companion object {
        private const val CLIENT_ASSERTION_MAX_LIFETIME = 120L
    }
}

/**
 * Result of parsing a `client_assertion` JWT before dispatching to either the
 * self-signed or federated authentication path. Kept internal to this file.
 */
private data class ParsedClientAssertion(
    val signedJWT: SignedJWT,
    val issuer: String,
    val subject: String,
)

/**
 * An authenticated client credential. Two variants are supported:
 *
 * - [SelfSigned]: issued by a tokendings-registered client with `iss == sub == clientId`
 *   and verified against the client's registered JWKS.
 * - [Federated]: issued by a configured external OIDC provider (e.g. a
 *   Kubernetes ServiceAccount issuer). `iss` and `sub` identify the workload
 *   and are later mapped to a registered client via [io.nais.security.oauth2.model.FederatedIdentity].
 *
 * Dispatch is based on whether the assertion's `iss` claim matches one of
 * the configured federated issuers. Federated auth is opt-in and disabled
 * unless [FederatedClientAuthProperties.isEnabled] is true.
 */
sealed class ClientCredential {
    abstract val signedJWT: SignedJWT

    data class SelfSigned(
        override val signedJWT: SignedJWT,
        val clientId: ClientId,
    ) : ClientCredential()

    data class Federated(
        override val signedJWT: SignedJWT,
        val issuer: String,
        val subject: String,
    ) : ClientCredential()

    companion object {
        const val JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    }
}

private fun SignedJWT.isWithinMaxLifetime(lifetime: Long): Boolean = this.expiresIn() <= lifetime

@WithSpan(kind = SpanKind.CLIENT)
suspend fun ApplicationCall.receiveTokenRequestContext(block: TokenRequestContext.From.() -> TokenRequestContext): TokenRequestContext =
    block.invoke(TokenRequestContext.From(this.receiveParameters()))
