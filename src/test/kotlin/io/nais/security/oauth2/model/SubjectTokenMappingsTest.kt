package io.nais.security.oauth2.model;

import io.kotest.matchers.equals.shouldBeEqual
import org.intellij.lang.annotations.Language
import org.junit.jupiter.api.Test;

internal class SubjectTokenMappingsTest {

    @Test
    fun `deserialize JSON to list of SubjectTokenMapping`() {
        @Language("JSON")
        val json = """
            {
                "https://authorization-server/.well-known/openid-configuration": { 
                    "claim1": {
                        "claim1value": "newclaim1value",
                        "claim1othervalue": "newclaim1othervalue"
                    },
                    "claim2": {
                        "claim2value": "newclaim2value"
                    }
                },
                "https://another-authorization-server/.well-known/openid-configuration": {
                    "claim1": {
                        "claim1value": "newclaim1value"
                    }
                }
            }
        """.trimIndent()

        val expected = mapOf(
            "https://authorization-server/.well-known/openid-configuration" to mapOf(
                "claim1" to mapOf(
                    "claim1value" to "newclaim1value",
                    "claim1othervalue" to "newclaim1othervalue"
                ),
                "claim2" to mapOf(
                    "claim2value" to "newclaim2value",
                ),
            ),
            "https://another-authorization-server/.well-known/openid-configuration" to mapOf(
                "claim1" to mapOf(
                    "claim1value" to "newclaim1value",
                ),
            )
        )

        val deserialized: IssuerClaimMappings = issuerClaimMappingsFromJson(json)
        deserialized shouldBeEqual expected
    }
}
