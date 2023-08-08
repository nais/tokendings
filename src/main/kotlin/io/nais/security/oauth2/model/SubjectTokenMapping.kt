package io.nais.security.oauth2.model

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue

typealias IssuerWellKnown = String
typealias Claim = String
typealias ClaimValue = String

typealias IssuerClaimMappings = Map<IssuerWellKnown, ClaimMappings>
typealias ClaimMappings = Map<Claim, ClaimValueMapping>
typealias ClaimValueMapping = Map<ClaimValue, ClaimValue>

fun issuerClaimMappingsFromJson(json: String): IssuerClaimMappings = jacksonObjectMapper()
    .readValue<IssuerClaimMappings>(json)
