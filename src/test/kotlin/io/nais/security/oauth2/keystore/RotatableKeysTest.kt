package io.nais.security.oauth2.keystore

import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.nais.security.oauth2.utils.generateRsaKey
import org.junit.jupiter.api.Test
import java.time.Duration
import java.time.LocalDateTime

internal class RotatableKeysTest {
    @Test
    fun `rotated keys should move current to previous, next to current and generated to next`() {
        val expiry = LocalDateTime.now()
        val initial =
            RotatableKeys(
                currentKey = generateRsaKey(),
                previousKey = generateRsaKey(),
                nextKey = generateRsaKey(),
                expiry = expiry,
            )
        val rotated = initial.rotate(Duration.ofDays(1))
        rotated.previousKey shouldBe initial.currentKey
        rotated.currentKey shouldBe initial.nextKey
        rotated.nextKey shouldNotBe initial.nextKey
        rotated.expiry.toSecondsOfMinutes() shouldBe expiry.plusDays(1).toSecondsOfMinutes()
    }

    private fun LocalDateTime.toSecondsOfMinutes() = this.withSecond(0).withNano(0)
}
