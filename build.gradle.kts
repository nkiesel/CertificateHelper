import java.nio.file.Path
import kotlin.io.path.createDirectories
import kotlin.io.path.writeText

plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.versions.update)
    alias(libs.plugins.docker)
    alias(libs.plugins.shadow)
    application
}

group = "nkiesel.org"
version = "3.2.0"

repositories {
    mavenCentral()
}

dependencies {
    implementation(libs.clikt)
    implementation(libs.clikt.markdown)
    implementation(libs.kotlin.serialization.json)
    implementation(libs.http4k.core)
    implementation(libs.http4k.client.okhttp)
    implementation(libs.http4k.server.netty)
    implementation(libs.http4k.template.handlebars)
    implementation(libs.mordant)
    implementation(libs.google.cloud.secretmanager)

    testImplementation(libs.junit.bom)
    testImplementation(libs.junit.jupiter)
}

kotlin {
    jvmToolchain(25)
}

application {
    mainClass = "CertificateHelperKt"
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform()
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

// Docker configuration
docker {
    javaApplication {
        baseImage.set("eclipse-temurin:21-jre-alpine")
        maintainer.set("nkiesel.org")
        ports.set(listOf(8080))
        images.set(listOf("nkiesel/certificate-helper:${project.version}", "nkiesel/certificate-helper:latest"))
        jvmArgs.set(listOf("-Xms256m", "-Xmx512m"))

        // Use the shadowJar task output
//        mainClassName.set(application.mainClass.get())

        // Set the command to run the web server on port 8080
        args.set(listOf("--web", "8080"))
    }
}

// Configure Docker to use the shadowJar instead of the standard jar
tasks.withType<com.bmuschko.gradle.docker.tasks.image.DockerBuildImage>().configureEach {
    dependsOn("jar")

    doFirst {
        copy {
            from(layout.buildDirectory.dir("libs").get().asFile)
            into(layout.buildDirectory.dir("docker/libs").get().asFile)
        }
    }
}
