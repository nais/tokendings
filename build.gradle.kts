import org.gradle.api.tasks.testing.logging.TestLogEvent
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

val assertjVersion = "3.23.1"
val flywayVersion = "9.1.2"
val h2Version = "2.1.214"
val hikaricpVersion = "5.0.1"
val junitJupiterVersion = "5.9.0"
val konfigVersion = "1.6.10.0"
val kotestVersion = "5.4.1"
val kotlinLoggingVersion = "2.1.23"
val kotlinVersion = "1.7.10"
val kotliqueryVersion = "1.8.0"
val ktorVersion = "2.1.0"
val logbackVersion = "1.2.11"
val logstashLogbackEncoderVersion = "7.2"
val micrometerRegistryPrometheusVersion = "1.9.3"
val mockOAuth2ServerVersion = "0.5.1"
val mockWebServerVersion = "4.10.0"
val mockkVersion = "1.12.5"
val nimbusSdkVersion = "9.41"
val postgresqlVersion = "42.4.1"
val testcontainersPostgresVersion = "1.17.3"

val mainClassKt = "io.nais.security.oauth2.TokenExchangeAppKt"

plugins {
    application
    kotlin("jvm") version "1.7.10"
    id("org.jmailen.kotlinter") version "3.11.1"
    id("com.github.johnrengelman.shadow") version "7.1.2"
    id("com.github.ben-manes.versions") version "0.42.0"
}

application {
    mainClass.set(mainClassKt)
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

apply(plugin = "org.jmailen.kotlinter")

repositories {
    mavenCentral()
    maven {
        url = uri("https://maven.pkg.jetbrains.space/public/p/ktor/eap")
        name = "ktor-eap"
    }
}

dependencies {
    implementation(kotlin("stdlib"))
    implementation("org.jetbrains.kotlin:kotlin-reflect:$kotlinVersion")
    implementation("org.jetbrains.kotlin:kotlin-script-runtime:$kotlinVersion")
    implementation("com.natpryce:konfig:$konfigVersion")
    implementation("io.github.microutils:kotlin-logging:$kotlinLoggingVersion")
    implementation("io.micrometer:micrometer-registry-prometheus:$micrometerRegistryPrometheusVersion")
    implementation("com.nimbusds:oauth2-oidc-sdk:$nimbusSdkVersion")
    implementation("com.github.seratch:kotliquery:$kotliqueryVersion")
    implementation("com.zaxxer:HikariCP:$hikaricpVersion")
    implementation("org.postgresql:postgresql:$postgresqlVersion")
    implementation("org.flywaydb:flyway-core:$flywayVersion")
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
    withType<org.jmailen.gradle.kotlinter.tasks.LintTask> {
        dependsOn("formatKotlin")
    }
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
    }

    withType<KotlinCompile> {
        kotlinOptions {
            jvmTarget = "17"
        }
    }

    withType<Test> {
        useJUnitPlatform()
        testLogging {
            events(TestLogEvent.PASSED, TestLogEvent.SKIPPED, TestLogEvent.FAILED)
        }
    }

    withType<Wrapper> {
        gradleVersion = "7.4.2"
    }

    "build" {
        dependsOn("shadowJar")
    }

    kotlinter {
        disabledRules = arrayOf("filename")
    }
}
