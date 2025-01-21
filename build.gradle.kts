import java.nio.file.Path
import kotlin.io.path.createDirectories
import kotlin.io.path.writeText

plugins {
    val kotlinVersion = "2.1.0"
    kotlin("jvm") version kotlinVersion
    kotlin("plugin.serialization") version kotlinVersion
    alias(libs.plugins.versions)
    alias(libs.plugins.versions.filter)
    alias(libs.plugins.versions.update)
    application
}

group = "nkiesel.org"
version = "3.0.0"

repositories {
    mavenCentral()
}

dependencies {
    implementation(libs.clikt)
    implementation(libs.clikt.markdown)
    implementation(libs.kotlin.serialization)
    implementation(libs.http4k.core)
    implementation(libs.http4k.client.okhttp)
    implementation(libs.mordant)
    implementation(libs.google.cloud.secretmanager)

    testImplementation(libs.junit.bom)
    testImplementation(libs.junit.jupiter)
}

kotlin {
    jvmToolchain(21)
}

application {
    mainClass = "CertificateHelperKt"
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform()
}

tasks.register<Jar>("uberJar") {
    archiveClassifier = "uber"
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    manifest { attributes(mapOf(
        "Main-Class" to application.mainClass,
        "Implementation-Version" to version,
    )) }

    from(sourceSets.main.get().output)

    dependsOn(configurations.runtimeClasspath)
    from({
        configurations.runtimeClasspath.get().filter { it.name.endsWith(".jar") }.map { zipTree(it) }
    }) {
        exclude("META-INF/*.RSA", "META-INF/*.SF", "META-INF/*.DSA")
    }
}

val versionFile: Path = layout.buildDirectory.file("generated/version").get().asFile.toPath()

sourceSets {
    main {
        kotlin {
            output.dir(versionFile.parent)
        }
    }
}

tasks.register("generateVersionProperties") {
    doLast {
        with(versionFile) {
            parent.createDirectories()
            writeText("$version")
        }
    }
}

tasks.named("processResources") {
    dependsOn("generateVersionProperties")
}
