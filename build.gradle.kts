import org.gradle.api.tasks.testing.logging.TestLogEvent
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.tasks.KotlinJvmCompile

val assertjVersion = "3.26.3"
val flywayVersion = "10.21.0"
val h2Version = "2.3.232"
val hikaricpVersion = "6.1.0"
val junitJupiterVersion = "5.11.3"
val konfigVersion = "1.6.10.0"
val kotestVersion = "5.9.1"
val kotlinLoggingVersion = "3.0.5"
val kotlinVersion = "2.0.21"
val kotliqueryVersion = "1.9.0"
val ktorVersion = "3.0.2"
val logbackVersion = "1.5.12"
val logstashLogbackEncoderVersion = "8.0"
val micrometerRegistryPrometheusVersion = "1.14.0"
val mockOAuth2ServerVersion = "2.1.10"
val mockWebServerVersion = "4.12.0"
val mockkVersion = "1.13.13"
val nimbusSdkVersion = "11.20.1"
val postgresqlVersion = "42.7.4"
val testcontainersPostgresVersion = "1.20.4"
val openTelemetryVersion = "1.44.1"
val openTelemetryAnnotationsVersion = "2.10.0"
val dropWizardVersion = "4.2.29"
val prometheusDropWizardVersion = "0.16.0"

val mainClassKt = "io.nais.security.oauth2.TokenExchangeAppKt"

plugins {
    application
    kotlin("jvm") version "2.0.21"
    id("org.jmailen.kotlinter") version "5.0.1"
    id("com.github.johnrengelman.shadow") version "8.1.1"
    id("com.github.ben-manes.versions") version "0.51.0"
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


configurations.all {
    resolutionStrategy {
        force("org.apache.commons:commons-compress:1.26.0")
    }
}

dependencies {
    implementation(kotlin("stdlib"))
    implementation("org.jetbrains.kotlin:kotlin-reflect:$kotlinVersion")
    implementation("org.jetbrains.kotlin:kotlin-script-runtime:$kotlinVersion")
    implementation("com.natpryce:konfig:$konfigVersion")
    implementation("io.github.microutils:kotlin-logging:$kotlinLoggingVersion")
    implementation("io.micrometer:micrometer-registry-prometheus-simpleclient:$micrometerRegistryPrometheusVersion")
    implementation("com.nimbusds:oauth2-oidc-sdk:$nimbusSdkVersion")
    implementation("com.github.seratch:kotliquery:$kotliqueryVersion")
    implementation("com.zaxxer:HikariCP:$hikaricpVersion")
    implementation("org.postgresql:postgresql:$postgresqlVersion")
    implementation("org.flywaydb:flyway-database-postgresql:$flywayVersion")
    implementation("io.ktor:ktor-server-netty-jvm:$ktorVersion")
    implementation("io.ktor:ktor-server-auth-jvm:$ktorVersion")
    implementation("io.ktor:ktor-server-auth-jwt-jvm:$ktorVersion")
    implementation("io.ktor:ktor-server-metrics-micrometer-jvm:$ktorVersion")
    implementation("io.ktor:ktor-server-content-negotiation-jvm:$ktorVersion")
    implementation("io.ktor:ktor-serialization-jackson-jvm:$ktorVersion")
    implementation("io.ktor:ktor-server-status-pages:$ktorVersion")
    implementation("io.ktor:ktor-server-call-logging:$ktorVersion")
    implementation("io.ktor:ktor-server-call-id:$ktorVersion")
    implementation("io.ktor:ktor-server-double-receive:$ktorVersion")
    implementation("io.ktor:ktor-server-forwarded-header:$ktorVersion")
    implementation("io.ktor:ktor-client-core-jvm:$ktorVersion")
    implementation("io.ktor:ktor-client-cio-jvm:$ktorVersion")
    implementation("io.ktor:ktor-client-content-negotiation-jvm:$ktorVersion")

    implementation("io.opentelemetry:opentelemetry-api:$openTelemetryVersion")
    implementation("io.opentelemetry:opentelemetry-extension-kotlin:$openTelemetryVersion")
    implementation("io.opentelemetry.instrumentation:opentelemetry-instrumentation-annotations:$openTelemetryAnnotationsVersion")
    implementation("io.prometheus:simpleclient_dropwizard:$prometheusDropWizardVersion")
    implementation("io.dropwizard.metrics:metrics-core:$dropWizardVersion")

    testImplementation("io.ktor:ktor-server-test-host-jvm:$ktorVersion")
    testImplementation("io.ktor:ktor-client-mock-jvm:$ktorVersion")
    runtimeOnly("ch.qos.logback:logback-classic:$logbackVersion")
    implementation("net.logstash.logback:logstash-logback-encoder:$logstashLogbackEncoderVersion")
    testImplementation("com.h2database:h2:$h2Version")
    testImplementation("no.nav.security:mock-oauth2-server:$mockOAuth2ServerVersion")
    testImplementation("org.assertj:assertj-core:$assertjVersion")
    testImplementation("com.squareup.okhttp3:mockwebserver:$mockWebServerVersion")
    testImplementation("io.mockk:mockk:$mockkVersion")
    testImplementation("io.kotest:kotest-runner-junit5-jvm:$kotestVersion") // for kotest framework
    testImplementation("io.kotest:kotest-assertions-core-jvm:$kotestVersion") // for kotest core jvm assertions
    testImplementation("io.kotest:kotest-property-jvm:$kotestVersion") // for kotest property test
    testImplementation("org.junit.jupiter:junit-jupiter-api:$junitJupiterVersion")
    testImplementation("org.jetbrains.kotlin:kotlin-test-junit5:$kotlinVersion")
    testImplementation("org.testcontainers:postgresql:$testcontainersPostgresVersion")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:$junitJupiterVersion")
}

tasks {
    withType<com.github.jengelman.gradle.plugins.shadow.tasks.ShadowJar> {
        archiveBaseName.set("app")
        archiveClassifier.set("")
        manifest {
            attributes(
                mapOf(
                    "Main-Class" to mainClassKt
                )
            )
        }
        mergeServiceFiles()
    }

    withType<KotlinJvmCompile>().configureEach {
        compilerOptions {
            jvmTarget.set(JvmTarget.JVM_21)
        }
    }

    withType<Test> {
        useJUnitPlatform()
        testLogging {
            events(TestLogEvent.PASSED, TestLogEvent.SKIPPED, TestLogEvent.FAILED)
        }
    }

    "build" {
        dependsOn("shadowJar")
    }
}
