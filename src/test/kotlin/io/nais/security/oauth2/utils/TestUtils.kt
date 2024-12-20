package io.nais.security.oauth2.utils

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.proc.JWSVerificationKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import com.nimbusds.oauth2.sdk.ErrorObject
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.mockk.every
import io.mockk.mockkStatic
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.time.Duration
import java.time.LocalDateTime
import java.util.UUID

fun jwkSet(): JWKSet =
    KeyPairGenerator
        .getInstance("RSA")
        .apply { initialize(2048) }
        .generateKeyPair()
        .let {
            RSAKey
                .Builder(it.public as RSAPublicKey)
                .privateKey(it.private as RSAPrivateKey)
                .keyID(UUID.randomUUID().toString())
                .keyUse(KeyUse.SIGNATURE)
                .build()
        }.let { JWKSet(it) }

fun SignedJWT.verifySignature(jwkSet: JWKSet): JWTClaimsSet =
    DefaultJWTProcessor<SecurityContext?>()
        .apply {
            jwsKeySelector = JWSVerificationKeySelector(JWSAlgorithm.RS256, ImmutableJWKSet(jwkSet))
        }.process(this, null)

@JsonInclude(JsonInclude.Include.NON_NULL)
data class ErrorResponse(
    val error_description: String,
    val error: String,
)

suspend infix fun HttpResponse.shouldBeObject(error: ErrorObject) {
    status.value shouldBe error.httpStatusCode
    val body = bodyAsText()
    body shouldNotBe null
    val errorResponse: ErrorResponse = jacksonObjectMapper().readValue(body)
    errorResponse.error shouldBe error.code
    errorResponse.error_description shouldBe error.description
}

fun mockkFuture(duration: Duration) {
    LocalDateTime.now().also {
        mockkStatic(LocalDateTime::class)
        every { LocalDateTime.now() } returns it.plus(duration)
    }
}
