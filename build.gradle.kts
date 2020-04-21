val ktorVersion = "1.3.2"
val mockkVersion = "1.9.3"
val kotlinResultVersion = "1.1.4"
val assertjVersion = "3.14.0"
val kotlinLoggingVersion = "1.7.8"
val logbackVersion = "1.2.3"
val nimbusSdkVersion = "7.3"
val mockWebServerVersion = "4.3.1"
val jacksonVersion = "2.10.1"
val junitJupiterVersion = "5.5.2"
val konfigVersion = "1.6.10.0"
val kotlinVersion = "1.3.61"
val freemarkerVersion = "2.3.29"
val micrometerRegistryPrometheusVersion = "1.3.5"
val logstashLogbackEncoderVersion = "5.2"
val mockOAuth2ServerVersion = "0.1.33"
val kotliqueryVersion = "1.3.1"
val hikarycpVersion = "3.4.2"
val postgresqlVersion = "42.2.12"
val flywayVersion = "6.3.3"
val h2Version = "1.4.200"
val testcontainersPostgresVersion = "1.14.0"
val kotlintestVersion = "3.4.2"

val mainClassKt = "io.nais.security.oauth2.TokenExchangeAppKt"

plugins {
    application
    kotlin("jvm") version "1.3.61"
    id("org.jmailen.kotlinter") version "2.2.0"
    id("com.github.johnrengelman.shadow") version "5.2.0"
}

application {
    mainClassName = mainClassKt
}

java {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
}

apply(plugin = "org.jmailen.kotlinter")

repositories {
    mavenCentral()
    jcenter()
    maven(url="https://dl.bintray.com/michaelbull/maven")
}

dependencies {
    implementation(kotlin("stdlib"))
    implementation("io.ktor:ktor-server-netty:$ktorVersion")
    implementation("io.ktor:ktor-auth:$ktorVersion")
    implementation("io.ktor:ktor-auth-jwt:$ktorVersion")
    implementation("io.ktor:ktor-client-core:$ktorVersion")
    implementation("io.ktor:ktor-client-apache:$ktorVersion")
    implementation("io.ktor:ktor-client-json:$ktorVersion")
    implementation("io.ktor:ktor-client-jackson:$ktorVersion")
    implementation("com.natpryce:konfig:$konfigVersion")
    implementation("io.github.microutils:kotlin-logging:$kotlinLoggingVersion")
    implementation("io.ktor:ktor-metrics-micrometer:$ktorVersion")
    implementation("io.micrometer:micrometer-registry-prometheus:$micrometerRegistryPrometheusVersion")
    implementation("io.ktor:ktor-jackson:$ktorVersion")
    implementation("com.nimbusds:oauth2-oidc-sdk:$nimbusSdkVersion")
    implementation("com.michael-bull.kotlin-result:kotlin-result:$kotlinResultVersion")
    implementation("com.github.seratch:kotliquery:$kotliqueryVersion")
    implementation("com.zaxxer:HikariCP:$hikarycpVersion")
    implementation("org.postgresql:postgresql:$postgresqlVersion")
    implementation("org.flywaydb:flyway-core:$flywayVersion")
    runtimeOnly("ch.qos.logback:logback-classic:$logbackVersion")
    implementation("net.logstash.logback:logstash-logback-encoder:$logstashLogbackEncoderVersion")
    testImplementation("com.h2database:h2:$h2Version")
    testImplementation("no.nav.security:mock-oauth2-server:$mockOAuth2ServerVersion")
    testImplementation("org.assertj:assertj-core:$assertjVersion")
    testImplementation("io.ktor:ktor-server-test-host:$ktorVersion")
    testImplementation("io.ktor:ktor-client-mock-jvm:$ktorVersion")
    testImplementation("com.squareup.okhttp3:mockwebserver:$mockWebServerVersion")
    testImplementation("io.mockk:mockk:$mockkVersion")
    testImplementation("io.kotlintest:kotlintest-core:$kotlintestVersion")
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

    withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile> {
        kotlinOptions {
            jvmTarget = "11"
        }
    }

    withType<Test> {
        useJUnitPlatform()
    }

    "build" {
        dependsOn("shadowJar")
    }
}
