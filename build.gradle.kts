plugins {
    kotlin("jvm") version "1.8.10"
    application
}

group = "io.nkiesel"
version = "1.5.0-alpha"

repositories {
    mavenCentral()
}

dependencies {
    implementation("com.github.ajalt.clikt:clikt:3.5.1")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.4.1")
    implementation("org.http4k:http4k-core:4.39.0.0")
    implementation("org.http4k:http4k-client-okhttp:4.39.0.0")

    testImplementation("org.junit.jupiter:junit-jupiter-api:5.9.2")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.9.2")
    testImplementation("io.kotest:kotest-assertions-core:5.5.5")
}

kotlin {
    jvmToolchain(17)
}

application {
    mainClass.set("CertificateHelperKt")
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform()
}

tasks.register<Jar>("uberJar") {
    archiveClassifier.set("uber")
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    manifest { attributes(mapOf("Main-Class" to application.mainClass)) }

    from(sourceSets.main.get().output)

    dependsOn(configurations.runtimeClasspath)
    from({
        configurations.runtimeClasspath.get().filter { it.name.endsWith("jar") }.map { zipTree(it) }
    })
}
