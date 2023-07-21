import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import kotlin.io.path.Path
import kotlin.io.path.createDirectories
import kotlin.io.path.writeText

plugins {
    kotlin("jvm") version "1.9.0"
    kotlin("plugin.serialization") version "1.9.0"
    application
}

group = "nkiesel.org"
version = "2.0.2"

repositories {
    mavenCentral()
}

dependencies {
    implementation("com.github.ajalt.clikt:clikt:4.1.0")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.5.1")
    implementation("org.http4k:http4k-core:5.4.0.0")
    implementation("org.http4k:http4k-client-okhttp:5.4.0.0")

    testImplementation("org.junit.jupiter:junit-jupiter-api:5.9.3")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.9.3")
    testImplementation("io.kotest:kotest-assertions-core:5.6.2")
}

kotlin {
    compilerOptions {
        jvmTarget = JvmTarget.JVM_17
    }
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

val versionFile = Path("$buildDir/generated/version")

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
