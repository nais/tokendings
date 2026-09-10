import org.gradle.api.tasks.testing.logging.TestLogEvent
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.tasks.KotlinJvmCompile

val mainClassKt = "io.nais.security.oauth2.TokenExchangeAppKt"

plugins {
    application
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlinter)
    alias(libs.plugins.dependency.updates)
}

kotlin {
    jvmToolchain(21)
}

application {
    mainClass.set(mainClassKt)
}

java {
    sourceCompatibility = JavaVersion.VERSION_21
    targetCompatibility = JavaVersion.VERSION_21
}

repositories {
    mavenCentral()
}

dependencies {
    // Platforms
    implementation(platform(libs.jackson.bom))
    implementation(platform(libs.netty.bom))

    // Kotlin
    implementation(libs.kotlin.reflect)
    implementation(libs.kotlin.script.runtime)
    testImplementation(libs.kotlin.test.junit5)

    // Observability
    implementation(libs.dropwizard.metrics)
    implementation(libs.micrometer.registry.prometheus)
    implementation(libs.opentelemetry.api)
    implementation(libs.opentelemetry.extension.kotlin)
    implementation(libs.opentelemetry.instrumentation.annotations)
    implementation(libs.prometheus.dropwizard)

    // Logging
    implementation(libs.kotlin.logging)
    runtimeOnly(libs.logback.classic)
    testImplementation(libs.logback.classic)
    implementation(libs.logstash.encoder)

    // Production
    implementation(libs.flyway.database.postgresql)
    implementation(libs.hikaricp)
    implementation(libs.konfig)
    implementation(libs.kotliquery)
    implementation(libs.ktor.client.cio)
    implementation(libs.ktor.client.content.negotiation)
    implementation(libs.ktor.client.core)
    implementation(libs.ktor.serialization.jackson)
    implementation(libs.ktor.server.auth)
    implementation(libs.ktor.server.auth.jwt)
    implementation(libs.ktor.server.call.id)
    implementation(libs.ktor.server.call.logging)
    implementation(libs.ktor.server.content.negotiation)
    implementation(libs.ktor.server.double.receive)
    implementation(libs.ktor.server.forwarded.header)
    implementation(libs.ktor.server.metrics.micrometer)
    implementation(libs.ktor.server.netty)
    implementation(libs.ktor.server.status.pages)
    implementation(libs.nimbus.oauth2.oidc)
    implementation(libs.postgresql)

    // Tests
    testImplementation(libs.assertj.core)
    testImplementation(libs.h2)
    testImplementation(libs.httpclient5)
    testImplementation(libs.junit.jupiter.api)
    testRuntimeOnly(libs.junit.jupiter.engine)
    testImplementation(libs.kotest.assertions.core) // for kotest core assertions
    testImplementation(libs.kotest.property) // for kotest property test
    testImplementation(libs.kotest.runner.junit5) // for kotest framework
    testImplementation(libs.ktor.client.mock)
    testImplementation(libs.ktor.server.test.host)
    testImplementation(libs.mock.oauth2.server)
    testImplementation(libs.mockk)
    testImplementation(libs.mockwebserver)
    testImplementation(libs.testcontainers.postgresql)
}

tasks {
    withType<KotlinJvmCompile>().configureEach {
        compilerOptions {
            jvmTarget.set(JvmTarget.JVM_21)
            freeCompilerArgs.add("-Xannotation-default-target=param-property")
        }
    }

    withType<Test> {
        useJUnitPlatform()
        testLogging {
            events(TestLogEvent.PASSED, TestLogEvent.SKIPPED, TestLogEvent.FAILED)
        }
    }

    named("dependencyUpdates", com.github.benmanes.gradle.versions.updates.DependencyUpdatesTask::class).configure {
        val immaturityLevels = listOf("rc", "cr", "m", "beta", "alpha", "preview") // order is important
        val immaturityRegexes = immaturityLevels.map { ".*[.\\-]$it[.\\-\\d]*".toRegex(RegexOption.IGNORE_CASE) }
        fun immaturityLevel(version: String): Int = immaturityRegexes.indexOfLast { version.matches(it) }
        rejectVersionIf { immaturityLevel(candidate.version) > immaturityLevel(currentVersion) }
    }
}
