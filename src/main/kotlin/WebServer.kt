package nkiesel.org

import org.http4k.core.*
import org.http4k.core.body.form
import org.http4k.lens.*
import org.http4k.routing.bind
import org.http4k.routing.routes
import org.http4k.server.Netty
import org.http4k.server.asServer
import java.io.File
import java.nio.file.Files
import kotlin.time.Duration
import org.http4k.routing.multipartForm

class WebServer {

    private val staticResources = StaticResources() // For serving static files like index.html

    private val routes = routes(
        "/" bind Method.GET to {
            // Serve index.html from resources
            val resourcePath = "/web/index.html"
            val inputStream = WebServer::class.java.getResourceAsStream(resourcePath)
            if (inputStream != null) {
                Response(Status.OK).body(inputStream.reader().readText()).header("Content-Type", "text/html; charset=utf-8")
            } else {
                Response(Status.NOT_FOUND).body("Resource not found: $resourcePath")
            }
        },
        "/processCertificate" bind Method.POST to { request ->
            handleProcessCertificate(request)
        },
        "/rootCAs" bind Method.GET to { request -> // New endpoint for listing root CAs
            handleListRootCAs(request)
        },
        // Serve other static assets if needed (e.g., CSS, JS)
        "static" bind staticResources
    )

    private val server = routes.asServer(Netty(8080))

    private fun handleListRootCAs(request: Request): Response {
        val certificateHelper = CertificateHelper()
        val argv = mutableListOf<String>()

        try {
            val filterValue = request.query("filter") ?: ".*" // Default to ".*" if no filter is provided
            
            argv.add("--rootCAs")
            // Clikt's optionalValue for --rootCAs means if the option is present but no value is given, it uses the default.
            // If a value is provided, it uses that.
            // So, if filterValue is ".*" (our default when nothing from client), it's like --rootCAs
            // If filterValue is something else, it's like --rootCAs=something
            // If filterValue from client is empty string, it's like --rootCAs=""
            // The CLI handles empty string for --rootCAs as "match nothing" effectively.
            // Or we can ensure ".*" if client sends empty.
            // Let's ensure ".*" if client sends empty or it's not provided.
            argv.add(if (filterValue.isBlank()) ".*" else filterValue)

            println("Executing CertificateHelper for rootCAs with argv: ${argv.joinToString(" ")}")
            certificateHelper.parse(argv)

            val output = certificateHelper.content.toString()
            return Response(Status.OK).body(output).header("Content-Type", "text/plain; charset=utf-8")

        } catch (e: CertificateHelperException) {
            return Response(Status.INTERNAL_SERVER_ERROR).body("CertificateHelper Error (RootCAs): ${e.message}")
        } catch (e: Exception) {
            e.printStackTrace() // Log for debugging
            return Response(Status.INTERNAL_SERVER_ERROR).body("An unexpected error occurred while listing RootCAs: ${e.message}")
        }
    }

    fun start() {
        println("Starting server on port 8080. Access at http://localhost:8080")
        server.start()
    }

    fun stop() {
        server.stop()
    }

    private fun handleProcessCertificate(request: Request): Response {
        val certificateHelper = CertificateHelper()
        val argv = mutableListOf<String>()
        var tempFile: File? = null

        try {
            val multipartForm = MultipartForm.from(request) // Use Http4k's multipart parsing

            // Helper to get form field value
            fun getField(name: String): String? = multipartForm.field(name)?.value
            fun getFlag(name: String): Boolean = multipartForm.field(name)?.value == "on" // HTML checkboxes send "on"

            // 1. Input Value and File
            val inputValue = getField("inputValue")
            val inputFilePart = multipartForm.file("inputFile")

            if (inputFilePart != null && inputFilePart.filename.isNotEmpty() && inputFilePart.length > 0) {
                tempFile = Files.createTempFile("upload_", inputFilePart.filename).toFile()
                inputFilePart.content.copyTo(tempFile.outputStream())
                argv.add("--input")
                argv.add(tempFile.absolutePath)
                certificateHelper.input = tempFile.absolutePath // Directly set if possible
                certificateHelper.useStdin = false
            } else if (!inputValue.isNullOrBlank()) {
                argv.add(inputValue) // This becomes the main argument
                certificateHelper.input = inputValue
                certificateHelper.useStdin = inputValue == "-"
            } else {
                 // Default to stdin if neither is provided, CertificateHelper defaults to "-" for inputOption
                 // No specific arg needed if CertificateHelper's default for inputOption is "-"
                 certificateHelper.input = "-"
                 certificateHelper.useStdin = true
            }


            // 2. Input Format
            getField("inputFormat")?.let {
                argv.add("--inputFormat")
                argv.add(it)
            }

            // 3. Output Format
            getField("outputFormat")?.let {
                argv.add("--outputFormat")
                argv.add(it)
            }

            // 4. Config Input Options (Flags)
            if (getFlag("hostName")) argv.add("--hostName")
            if (getFlag("jwe")) argv.add("--jwe")
            if (getFlag("tls")) argv.add("--tls")
            if (getFlag("bundle")) argv.add("--bundle")

            // 5. Config Key
            getField("configKey")?.let {
                if (it.isNotBlank()) {
                    argv.add("--key")
                    argv.add(it)
                }
            }

            // 6. Secret Name
            getField("secretName")?.let {
                if (it.isNotBlank()) {
                    argv.add("--secretName")
                    argv.add(it)
                }
            }

            // 7. Port
            getField("port")?.let {
                if (it.isNotBlank()) {
                    try {
                        it.toInt() // Validate
                        argv.add("--port")
                        argv.add(it)
                    } catch (e: NumberFormatException) {
                        return Response(Status.BAD_REQUEST).body("Invalid port number: $it")
                    }
                }
            }

            // 8. Certificate Index
            getField("certIndex")?.let {
                if (it.isNotBlank()) {
                    // Validate format (simple check, Clikt will do more)
                    if (it.matches(Regex("^\\d+(,\\d+)*\$"))) {
                        argv.add("--certIndex")
                        argv.add(it)
                    } else if (it.isNotEmpty()){ // Only error if not empty and invalid
                        return Response(Status.BAD_REQUEST).body("Invalid certificate index format: $it. Expected comma-separated numbers.")
                    }
                }
            }

            // 9. Timeout
            getField("timeout")?.let {
                if (it.isNotBlank()) {
                    try {
                        Duration.parse(it) // Validate
                        argv.add("--timeout")
                        argv.add(it)
                    } catch (e: IllegalArgumentException) {
                        return Response(Status.BAD_REQUEST).body("Invalid timeout format: $it. Expected format like '5s', '1m30s'.")
                    }
                }
            }
            
            // 10. Verbose
            if (getFlag("verbose")) argv.add("--verbose")

            // Run CertificateHelper
            println("Executing CertificateHelper with argv: ${argv.joinToString(" ")}")
            certificateHelper.parse(argv) // Use parse to avoid System.exit

            val output = certificateHelper.content.toString()
            return Response(Status.OK).body(output).header("Content-Type", "text/plain; charset=utf-8")

        } catch (e: CertificateHelperException) {
            // Error from CertificateHelper logic
            return Response(Status.INTERNAL_SERVER_ERROR).body("CertificateHelper Error: ${e.message}")
        } catch (e: LensFailure) {
            // Error parsing form fields (e.g., required field missing, type mismatch if using Http4k lenses directly)
            return Response(Status.BAD_REQUEST).body("Bad Request: ${e.message}\n${e.failures.joinToString("\n")}")
        } 
        catch (e: Exception) {
            // Other unexpected errors
            e.printStackTrace() // Log for debugging
            return Response(Status.INTERNAL_SERVER_ERROR).body("An unexpected error occurred: ${e.message}")
        } finally {
            tempFile?.delete() // Clean up temporary file
        }
    }
}

// For serving static files if needed (e.g. CSS, JS).
// This is a basic implementation. For more complex needs, consider a dedicated static file handler.
class StaticResources : HttpHandler {
    override fun invoke(request: Request): Response {
        val path = request.uri.path.removePrefix("/static/").ifEmpty { return Response(Status.NOT_FOUND) }
        val resourcePath = "/web/$path" // Assumes static files are in src/main/resources/web/
        val inputStream = WebServer::class.java.getResourceAsStream(resourcePath)

        return if (inputStream != null) {
            val contentType = when {
                path.endsWith(".css") -> "text/css"
                path.endsWith(".js") -> "application/javascript"
                path.endsWith(".png") -> "image/png"
                path.endsWith(".jpg") -> "image/jpeg"
                path.endsWith(".ico") -> "image/x-icon"
                else -> "application/octet-stream"
            }
            Response(Status.OK).body(inputStream).header("Content-Type", contentType)
        } else {
            Response(Status.NOT_FOUND).body("Resource not found: $resourcePath")
        }
    }
}

fun main() { // For testing the server independently
    WebServer().start()
}
