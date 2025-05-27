// This class is in the same package as CertificateHelper
import org.http4k.core.*
import org.http4k.core.Method.*
import org.http4k.core.Status.Companion.OK
import org.http4k.routing.bind
import org.http4k.routing.routes
import org.http4k.routing.static
import org.http4k.server.Netty
import org.http4k.server.asServer
import org.http4k.template.HandlebarsTemplates
import org.http4k.template.ViewModel
import org.http4k.template.TemplateRenderer
import org.http4k.template.ViewNotFound
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.PrintStream
import java.nio.file.Files
import kotlin.io.path.createTempFile

// View models for templates
data class IndexViewModel(val title: String = "Certificate Helper") : ViewModel
data class ResultViewModel(val title: String = "Certificate Helper - Result", val result: String) : ViewModel

class WebServer(private val port: Int = 8080) {
    // Use classpath for templates instead of file system path
    private val renderer = HandlebarsTemplates().CachingClasspath("templates")

    // Run CertificateHelper with the given args
    private fun runCertificateHelper(args: Array<String>): String {
        val command = mutableListOf("java", "-jar")

        // Find the jar file in the build directory
        val jarFile = File("build/libs").listFiles()
            ?.filter { it.name.endsWith(".jar") && !it.name.contains("sources") }
            ?.maxByOrNull { it.lastModified() }
            ?.absolutePath
            ?: return "Error: Could not find CertificateHelper JAR file"

        command.add(jarFile)
        command.addAll(args.toList())

        val process = ProcessBuilder(command)
            .redirectErrorStream(true)
            .start()

        val output = process.inputStream.bufferedReader().use { it.readText() }
        process.waitFor()

        return output
    }

    // Parse form data from request
    private fun parseFormData(request: Request): Map<String, String> {
        val formData = request.bodyString()
        return if (formData.isNotEmpty()) {
            formData.split("&")
                .mapNotNull { param -> 
                    val parts = param.split("=", limit = 2)
                    if (parts.size == 2) {
                        parts[0] to java.net.URLDecoder.decode(parts[1], "UTF-8")
                    } else null
                }
                .toMap()
        } else {
            emptyMap()
        }
    }

    // HTTP routes
    private val app = routes(
        "/" bind GET to { 
            Response(OK).body(renderTemplate(renderer, IndexViewModel()))
        },

        "/server" bind POST to { request ->
            val formData = parseFormData(request)
            val server = formData["server"] ?: ""
            val portStr = formData["port"] ?: "443"
            val outputFormat = formData["outputFormat"] ?: "SUMMARY"
            val certIndex = formData["certIndex"] ?: ""

            val result = if (server.isNotEmpty()) {
                val args = mutableListOf("-f", "SERVER", "-p", portStr, "-t", outputFormat)

                if (certIndex.isNotEmpty()) {
                    args.add("-c")
                    args.add(certIndex)
                }

                args.add(server)
                runCertificateHelper(args.toTypedArray())
            } else {
                "Please enter a server name"
            }

            Response(OK).body(renderTemplate(renderer, ResultViewModel(result = result)))
        },

        "/pem" bind POST to { request ->
            val formData = parseFormData(request)
            val pemData = formData["pemData"] ?: ""
            val outputFormat = formData["outputFormat"] ?: "SUMMARY"
            val certIndex = formData["certIndex"] ?: ""

            val result = if (pemData.isNotEmpty()) {
                // Create a temporary file for the PEM data
                val tempFile = createTempFile(suffix = ".pem").toFile()
                try {
                    tempFile.writeText(pemData)
                    val args = mutableListOf("-f", "PEM", "-t", outputFormat)

                    if (certIndex.isNotEmpty()) {
                        args.add("-c")
                        args.add(certIndex)
                    }

                    args.add(tempFile.absolutePath)
                    runCertificateHelper(args.toTypedArray())
                } finally {
                    tempFile.delete()
                }
            } else {
                "Please enter PEM data"
            }

            Response(OK).body(renderTemplate(renderer, ResultViewModel(result = result)))
        },

        "/config" bind POST to { request ->
            val formData = parseFormData(request)
            val configData = formData["configData"] ?: ""
            val configKey = formData["configKey"] ?: ""
            val outputFormat = formData["outputFormat"] ?: "SUMMARY"
            val option = formData["option"] ?: ""
            val certIndex = formData["certIndex"] ?: ""

            val args = mutableListOf("-f", "CONFIG", "-t", outputFormat)

            if (configKey.isNotEmpty()) {
                args.add("-k")
                args.add(configKey)
            }

            if (certIndex.isNotEmpty()) {
                args.add("-c")
                args.add(certIndex)
            }

            when (option) {
                "hostName" -> args.add("-n")
                "jwe" -> args.add("-j")
                "tls" -> args.add("--tls")
                "bundle" -> args.add("-b")
            }

            val result = if (configData.isNotEmpty() && configKey.isNotEmpty()) {
                // Create a temporary file for the config data
                val tempFile = createTempFile(suffix = ".json").toFile()
                try {
                    tempFile.writeText(configData)
                    runCertificateHelper(args.toTypedArray() + tempFile.absolutePath)
                } finally {
                    tempFile.delete()
                }
            } else {
                "Please enter config data and key"
            }

            Response(OK).body(renderTemplate(renderer, ResultViewModel(result = result)))
        },

        "/static" bind static()
    )

    // Helper function to render templates
    private fun renderTemplate(renderer: TemplateRenderer, viewModel: ViewModel): String {
        return try {
            renderer(viewModel)
        } catch (e: ViewNotFound) {
            // Log the error
            println("Template not found for ${viewModel.javaClass.simpleName}: ${e.message}")

            // Return a simple fallback template
            when (viewModel) {
                is IndexViewModel -> """
                    <!DOCTYPE html>
                    <html>
                    <head>
                        <title>${viewModel.title}</title>
                    </head>
                    <body>
                        <h1>${viewModel.title}</h1>
                        <p>Welcome to Certificate Helper Web Interface</p>
                        <p>Error: Template not found. Please check your installation.</p>
                    </body>
                    </html>
                """.trimIndent()

                is ResultViewModel -> """
                    <!DOCTYPE html>
                    <html>
                    <head>
                        <title>${viewModel.title}</title>
                    </head>
                    <body>
                        <h1>${viewModel.title}</h1>
                        <pre>${viewModel.result}</pre>
                        <p><a href="/">Back to home</a></p>
                    </body>
                    </html>
                """.trimIndent()

                else -> "Error: Template not found for ${viewModel.javaClass.simpleName}"
            }
        }
    }

    // Start the server
    fun start() {
        val server = app.asServer(Netty(port))
        server.start()
        println("Server started on port $port")
        println("Open http://localhost:$port in your browser")
    }
}
