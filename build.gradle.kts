import java.nio.file.Path
import kotlin.io.path.createDirectories
import kotlin.io.path.writeText

plugins {
    val kotlinVersion = "2.1.20"
    kotlin("multiplatform") version kotlinVersion
    kotlin("plugin.serialization") version kotlinVersion
    alias(libs.plugins.versions)
    alias(libs.plugins.versions.filter)
    alias(libs.plugins.versions.update)
    alias(libs.plugins.docker)
    application
}

group = "nkiesel.org"
version = "3.0.1"

repositories {
    mavenCentral()
}

dependencies {
    // Test dependencies remain at the root level
    testImplementation(libs.junit.bom)
    testImplementation(libs.junit.jupiter)
}

kotlin {
    jvm {
        withJava()
        compilations.all {
            kotlinOptions.jvmTarget = "21"
        }
    }

    macosArm64 {
        binaries {
            executable {
                entryPoint = "main"
                baseName = "certificate-helper"
            }
        }
    }

    sourceSets {
        val commonMain by getting {
            dependencies {
                implementation(libs.kotlin.serialization)
                implementation(libs.clikt)
                implementation(libs.mordant)
            }
        }

        val jvmMain by getting {
            dependencies {
                implementation(libs.clikt.markdown)
                implementation(libs.http4k.core)
                implementation(libs.http4k.client.okhttp)
                implementation(libs.http4k.server.netty)
                implementation(libs.http4k.template.handlebars)
                implementation(libs.google.cloud.secretmanager)
            }
        }

        val macosArm64Main by getting {
            dependencies {
                // Native-specific dependencies can be added here
            }
        }
    }

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

// Native compilation task
tasks.register("nativeBuild") {
    dependsOn("macosArm64Binaries")
    doLast {
        println("Native binary built at: ${layout.buildDirectory.get()}/bin/macosArm64/releaseExecutable/certificate-helper.kexe")
    }
}

// Docker configuration
docker {
    javaApplication {
        baseImage.set("eclipse-temurin:21-jre-alpine")
        maintainer.set("nkiesel.org")
        ports.set(listOf(8080))
        images.set(listOf("nkiesel/certificate-helper:${project.version}", "nkiesel/certificate-helper:latest"))
        jvmArgs.set(listOf("-Xms256m", "-Xmx512m"))

        // Use the uberJar task output
        mainClassName.set(application.mainClass.get())

        // Set the command to run the web server on port 8080
        args.set(listOf("--web", "8080"))
    }
}

// Configure Docker to use the uberJar instead of the standard jar
tasks.withType<com.bmuschko.gradle.docker.tasks.image.DockerBuildImage>().configureEach {
    dependsOn("uberJar")

    doFirst {
        // Copy the uberJar to the Docker build directory
        copy {
            from(tasks.named("uberJar"))
            rename { "app.jar" }
            into("${buildDir}/docker/build")
        }
    }
}
