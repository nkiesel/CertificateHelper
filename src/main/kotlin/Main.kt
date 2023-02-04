import java.io.InputStream
import java.io.PrintWriter
import java.io.StringWriter
import java.nio.file.Path
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
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.X509TrustManager
import kotlin.io.path.Path
import kotlin.io.path.inputStream
import kotlin.io.path.isDirectory
import kotlin.io.path.isReadable
import kotlin.io.path.isRegularFile
import kotlin.io.path.readText
import kotlin.io.path.useDirectoryEntries
import kotlin.io.path.writeText
import kotlinx.cli.ArgParser
import kotlinx.cli.ArgType
import kotlinx.cli.default
import kotlinx.cli.required
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
    CertificateHelper(System.getProperty("sun.java.command") ?: "CertificateHelper", args)
}

class CertificateHelper(name: String, args: Array<String>) {

    private val parser = ArgParser(name)
    private val inputFormat by parser.option(ArgType.Choice<InputFormat>(), shortName = "f", description = "Input format").default(InputFormat.SERVER)
    private val input by parser.option(ArgType.String, shortName = "i", description = "Input").required()
    private val key by parser.option(ArgType.String, shortName = "k", description = "Config key")
    private val port by parser.option(ArgType.Int, shortName = "p", description = "server port").default(443)
    private val outputFormat by parser.option(ArgType.Choice<OutputFormat>(), shortName = "t", description = "Output format").default(OutputFormat.SUMMARY)
    private val output by parser.option(ArgType.String, shortName = "o", description = "Output (- for stdout)").default("-")
    private val certIndex by parser.option(ArgType.Int, shortName = "c", description = "certificate index")

    private val s = StringWriter()
    private val writer = PrintWriter(s)

    init {
        parser.parse(args)

        when (inputFormat) {
            InputFormat.PEM, InputFormat.BASE64 -> handlePEM()
            InputFormat.SERVER -> handleServer()
            InputFormat.CONFIG -> handleConfig()
        }
        writer.flush()

        var final = s.toString()
        if (outputFormat == OutputFormat.BASE64) final = final.base64Encode()
        if (output == "-") println(final) else Path(output).writeText(final)
    }

    private fun handlePEM() {
        val path = Path(input)
        if (path.isReadable()) {
            if (path.isRegularFile()) {
                chain(path)
            } else if (path.isDirectory()) {
                path.useDirectoryEntries("*") { paths ->
                    // Only use 1-context for directories
                    paths.filter { it.isReadable() && it.isRegularFile() }.forEach {
                        chain(it)
                    }
                }
            } else {
                info(input, "Not a regular file or directory")
            }
        } else {
            info(input, "Not readable")
        }
    }

    private fun handleServer() {
        val host = input
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

        val socketFactory: SSLSocketFactory = SSLContext.getInstance("TLS").apply {
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
            } catch (e: SSLException) {
            }
        }

        val chain = tm.chain
        if (chain != null) {
            for (cert in chain.withIndex()) {
                if (certIndex == null || certIndex == cert.index) {
                    certificate(host, cert.value)
                }
            }
        } else {
            info(host, "Could not obtain server certificate chain")
        }
    }

    private fun handleConfig() {
        val config = input
        val configKey = key
        if (configKey.isNullOrEmpty()) {
            info(input, "Key is required for config files")
            return
        }
        var json: JsonElement? = Json.parseToJsonElement(Path(config).readText())
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
        chain(config, json.jsonPrimitive.content.base64Decode().inputStream())
    }

    private fun chain(name: String, inputStream: InputStream) {
        inputStream.use { stream ->
            try {
                for (cert in certificateFactory.generateCertificates(stream).withIndex()) {
                    if (certIndex == null || certIndex == cert.index) {
                        certificate(name, cert.value)
                    }
                }
            } catch (e: Exception) {
                info(name, "Could not read as X509 certificate")
            }
        }
    }

    private fun chain(path: Path) {
        val inputStream = when(inputFormat) {
            InputFormat.BASE64 -> path.readText().base64Decode().inputStream()
            else -> path.inputStream()
        }
        chain(path.toString(), inputStream)
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
