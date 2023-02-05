import java.io.InputStream
import java.io.PrintWriter
import java.io.StringWriter
import java.security.MessageDigest
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.HexFormat
import javax.naming.ldap.LdapName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLException
import javax.net.ssl.SSLSocket
import javax.net.ssl.X509TrustManager
import kotlin.io.path.Path
import kotlin.io.path.inputStream
import kotlin.io.path.isReadable
import kotlin.io.path.isRegularFile
import kotlin.io.path.readText
import kotlin.io.path.writeText
import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.core.context
import com.github.ajalt.clikt.output.CliktHelpFormatter
import com.github.ajalt.clikt.parameters.options.default
import com.github.ajalt.clikt.parameters.options.option
import com.github.ajalt.clikt.parameters.options.split
import com.github.ajalt.clikt.parameters.types.enum
import com.github.ajalt.clikt.parameters.types.int
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive


private val sha256 = MessageDigest.getInstance("SHA-256")
private val hexFormat = HexFormat.ofDelimiter("").withUpperCase()
private val certificateFactory = CertificateFactory.getInstance("X.509")
private val pemEncoder = Base64.getMimeEncoder(64, "\n".toByteArray())

fun ByteArray.sha256(): ByteArray = sha256.digest(this)
fun ByteArray.hex(): String = hexFormat.formatHex(this)
fun ByteArray.sha256Hex(): String = sha256().hex()
fun String.base64Decode(): ByteArray = Base64.getDecoder().decode(this)
fun ByteArray.base64Encode(): String = Base64.getEncoder().encodeToString(this)
fun String.base64Encode(): String = encodeToByteArray().base64Encode()

enum class InputFormat {
    SERVER, CONFIG, PEM, BASE64
}

enum class OutputFormat {
    PEM, SUMMARY, BASE64, TEXT
}

fun main(args: Array<String>) {
    CertificateHelper().main(args)
}

class CertificateHelper : CliktCommand() {
    init {
        context { helpFormatter = CliktHelpFormatter(showDefaultValues = true, showRequiredTag = true) }
    }

    private val input by option("-i", "--input", help = "Input file or server name; - for stdin")
        .default("-")
    private val inputFormat by option("-f", "--inputFormat", help = "Input format")
        .enum<InputFormat>().default(InputFormat.SERVER)
    private val key by option("-k", "--key", help = "Config key")
    private val port by option("-p", "--port", help = "Server port")
        .int().default(443)
    private val output by option("-o", "--output", help = "Output file name; - for stdout")
        .default("-")
    private val outputFormat by option("-t", "--outputFormat", help = "Output format")
        .enum<OutputFormat>().default(OutputFormat.SUMMARY)
    private val certIndex: List<Int> by option("-c", "--certIndex", help = "Certificate indices (comma-separated)")
        .int().split(",").default(emptyList(), defaultForHelp = "all certificates")

    private val content = StringWriter()
    private val writer = PrintWriter(content)

    override fun run() {
        when (inputFormat) {
            InputFormat.PEM, InputFormat.BASE64 -> handlePEM()
            InputFormat.SERVER -> handleServer()
            InputFormat.CONFIG -> handleConfig()
        }
        writer.flush()

        val final = content.toString().let { if (outputFormat == OutputFormat.BASE64) it.base64Encode() else it }
        if (output == "-") println(final) else Path(output).writeText(final)
    }

    private fun handlePEM() {
        if (input == "-") {
            val stdin = generateSequence(::readLine).joinToString("\n")
            val inputStream = when (inputFormat) {
                InputFormat.BASE64 -> stdin.base64Decode().inputStream()
                else -> stdin.byteInputStream()
            }
            chain(input, inputStream)
        } else {
            val path = Path(input)
            if (path.isReadable() && path.isRegularFile()) {
                val inputStream = when (inputFormat) {
                    InputFormat.BASE64 -> path.readText().base64Decode().inputStream()
                    else -> path.inputStream()
                }
                chain(path.toString(), inputStream)
            } else {
                info(input, "Not a readable regular file")
            }
        }
    }

    private fun handleServer() {
        val host = if (input == "-") readln() else input
        val tm = object : X509TrustManager {
            var chain: Array<X509Certificate>? = null

            override fun getAcceptedIssuers(): Array<X509Certificate> {
                throw UnsupportedOperationException()
            }

            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {
                throw UnsupportedOperationException()
            }

            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
                this.chain = chain
            }
        }

        val socketFactory = SSLContext.getInstance("TLS").apply {
            init(null, arrayOf<X509TrustManager>(tm), null)
        }.socketFactory

        val sslSocket = try {
            socketFactory.createSocket(host, port) as SSLSocket
        } catch (e: Exception) {
            info(host, "Could not connect")
            return
        }
        sslSocket.use {
            try {
                it.startHandshake()
            } catch (_: SSLException) {
            }
        }

        val chain = tm.chain
        if (chain == null) {
            info(host, "Could not obtain server certificate chain")
            return
        }
        for (cert in chain.withIndex()) {
            if (certIndex.isEmpty() || cert.index in certIndex) {
                certificate(host, cert.value)
            }
        }
    }

    private fun handleConfig() {
        val config = if (input == "-") {
            generateSequence(::readLine).joinToString("\n")
        } else {
            Path(input).readText()
        }
        val configKey = key
        if (configKey.isNullOrEmpty()) {
            info(input, "Key is required for config files")
            return
        }
        var json: JsonElement? = Json.parseToJsonElement(config)
        val keys = configKey.split(".").toMutableList()
        if (keys.size == 1) {
            keys += listOf("tls", "caBundleBase64")
        }
        for (comp in keys) {
            json = json?.jsonObject?.get(comp)
        }
        if (json == null) {
            info(input, "Cannot extract $configKey")
            return
        }
        chain(input, json.jsonPrimitive.content.base64Decode().inputStream())
    }

    private fun chain(name: String, inputStream: InputStream) {
        inputStream.use { stream ->
            try {
                for (cert in certificateFactory.generateCertificates(stream).withIndex()) {
                    if (certIndex.isEmpty() || cert.index in certIndex) {
                        certificate(name, cert.value)
                    }
                }
            } catch (e: Exception) {
                info(name, "Could not read as X509 certificate")
            }
        }
    }

    private fun info(name: String, info: String) {
        println("\n$name: $info")
    }

    private fun certificate(name: String, cert: Certificate) {
        when (outputFormat) {
            OutputFormat.SUMMARY -> certificateSummary(name, cert)
            OutputFormat.TEXT -> certificateText(name, cert)
            OutputFormat.BASE64, OutputFormat.PEM -> certificatePem(cert)
        }
    }

    private fun certificatePem(cert: Certificate) {
        with(writer) {
            println("-----BEGIN CERTIFICATE-----")
            println(pemEncoder.encodeToString(cert.encoded))
            println("-----END CERTIFICATE-----")
        }
    }

    private fun certificateText(name: String, cert: Certificate) {
        with(writer) {
            println(name)
            println(cert)
        }
    }

    private fun certificateSummary(name: String, cert: Certificate) {
        fun dns(altName: List<*>): String? = if (altName[0] as Int == 2) altName[1] as String else null

        try {
            with(writer) {
                with(cert as X509Certificate) {
                    println("\n$name: X509 certificate for ${LdapName(subjectX500Principal.name).rdns.last().value}")
                    println("\tSHA256 fingerprint: ${encoded.sha256Hex()}")
                    println("\tSHA256 public key: ${publicKey.encoded.sha256Hex()}")
                    println("\tExpires: ${this.notAfter.toInstant()}")
                    if (!subjectAlternativeNames.isNullOrEmpty()) {
                        println("\tDNS names: ${subjectAlternativeNames.mapNotNull { dns(it) }}")
                    }
                }
            }
        } catch (e: Exception) {
            info(name, "Could not read as X509 certificate")
        }
    }
}
