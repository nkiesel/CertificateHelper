import java.nio.file.Path
import kotlin.io.path.createDirectories
import kotlin.io.path.writeText

plugins {
    kotlin("jvm") version "1.9.23"
    kotlin("plugin.serialization") version "1.9.23"
    application
}

group = "nkiesel.org"
version = "2.6.1"

repositories {
    mavenCentral()
}

dependencies {
    implementation("com.github.ajalt.clikt:clikt:4.2.2")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.6.3")
    implementation("org.http4k:http4k-core:5.14.0.0")
    implementation("org.http4k:http4k-client-okhttp:5.14.0.0")
    implementation("com.github.ajalt.mordant:mordant:2.3.0")

    testImplementation("org.junit.jupiter:junit-jupiter-api:5.10.2")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.10.2")
    testImplementation("io.kotest:kotest-assertions-core:5.8.0")
}

kotlin {
    jvmToolchain(17)
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
    })
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
