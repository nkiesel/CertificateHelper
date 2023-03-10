import java.io.InputStream
import java.io.PrintWriter
import java.io.StringWriter
import java.net.InetSocketAddress
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.*
import javax.naming.ldap.LdapName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLException
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager
import javax.security.auth.x500.X500Principal
import kotlin.io.path.*
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds
import com.github.ajalt.clikt.completion.CompletionCandidates
import com.github.ajalt.clikt.completion.completionOption
import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.core.context
import com.github.ajalt.clikt.output.CliktHelpFormatter
import com.github.ajalt.clikt.parameters.options.convert
import com.github.ajalt.clikt.parameters.options.default
import com.github.ajalt.clikt.parameters.options.flag
import com.github.ajalt.clikt.parameters.options.option
import com.github.ajalt.clikt.parameters.options.split
import com.github.ajalt.clikt.parameters.options.versionOption
import com.github.ajalt.clikt.parameters.types.enum
import com.github.ajalt.clikt.parameters.types.int
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.http4k.client.OkHttp
import org.http4k.client.PreCannedOkHttpClients
import org.http4k.core.Method
import org.http4k.core.Request
import org.http4k.core.Uri
import org.http4k.core.appendToPath


private val sha256 = MessageDigest.getInstance("SHA-256")
private val hexFormat = HexFormat.ofDelimiter("").withUpperCase()
private val certificateFactory = CertificateFactory.getInstance("X.509")
private val pemEncoder = Base64.getMimeEncoder(64, "\n".toByteArray())
private val tlsContext = SSLContext.getInstance("TLS")

fun ByteArray.sha256(): ByteArray = sha256.digest(this)
fun ByteArray.hex(): String = hexFormat.formatHex(this)
fun ByteArray.sha256Hex(): String = sha256().hex()
fun String.base64Decode(): ByteArray = Base64.getDecoder().decode(this)
fun ByteArray.base64Encode(): String = Base64.getEncoder().encodeToString(this)
fun String.base64Encode(): String = encodeToByteArray().base64Encode()

enum class InputFormat {
    SERVER, JSON, PEM, BASE64, VAULT, CONFIG
}

enum class OutputFormat {
    SUMMARY, TEXT, PEM, BASE64, CONFIG
}

private const val VAULT_ADDR = "https://hashicorp-vault.corp.creditkarma.com:6661"
private const val VERSION = "1.6.0-alpha"

private val keyUsages = arrayOf(
    "Digital signature",
    "Non-repudiation",
    "Key encipherment",
    "Data encipherment",
    "Key agreement",
    "Certificate signing",
    "CRL signing",
    "Encipher only",
    "Decipher only",
)

private val extendedKeyUsages = mapOf(
    "1.3.6.1.5.5.7.3.1" to "Server authentication",
    "1.3.6.1.5.5.7.3.2" to "Client authentication",
    "1.3.6.1.5.5.7.3.3" to "Code signing",
    "1.3.6.1.5.5.7.3.4" to "Email",
    "1.3.6.1.5.5.7.3.8" to "Timestamping",
    "1.3.6.1.5.5.7.3.9[a]" to "OCSP Signing",
)

fun main(args: Array<String>) {
    CertificateHelper().main(args)
}

class CertificateHelper : CliktCommand(
    name = "ch",
    help = """
        Reads or updates certificates from server, config, file, or vault.  Example:
        ```
        ch -f server -i api.github.com
        ```
    """.trimIndent(),
    epilog = """
    Vault operations need a current vault token. This can be provided either via
    the environment variable VAULT_TOKEN, or via the file ${'$'}HOME/.vault-token.
    The latter is automatically created when using the command "vault login". The
    token (normally valid for 24 hours) can be generated after signing into the vault
    using the URL (requires Okta Yubikey authentication)
    ${VAULT_ADDR}/ui/vault/auth?with=okta_oidc
    and then using the "Copy Token" menu entry from the top-right user menu.
    """.trimIndent(),
) {
    init {
        context {
            helpFormatter = CliktHelpFormatter(
                showDefaultValues = true,
                showRequiredTag = true,
                maxColWidth = 80,
                maxWidth = 130
            )
        }
        completionOption()
        versionOption(javaClass.getResourceAsStream("version").bufferedReader().use { it.readLine() }, names = setOf("-v", "--version"))
    }

    private val input by option(
        "-i", "--input", completionCandidates = CompletionCandidates.Path,
        help = "Input file or server name; - for stdin"
    ).default("-")
    private val inputFormat by option("-f", "--inputFormat", help = "Input format").enum<InputFormat>()
        .default(InputFormat.CONFIG)
    private val hostName by option("-n", "--hostName", help = "Server name from config key").flag()
    private val jwe by option("-j", "--jwe", help = "JWE info from config").flag()
    private val key by option("-k", "--key", help = "Config key")
    private val port by option("-p", "--port", help = "Server port").int().default(443)
    private val output by option(
        "-o", "--output", completionCandidates = CompletionCandidates.Path,
        help = "Output file name; - for stdout"
    ).default("-")
    private val outputFormat by option("-t", "--outputFormat", help = "Output format").enum<OutputFormat>()
        .default(OutputFormat.SUMMARY)
    private val certIndex: List<Int> by option("-c", "--certIndex", help = "Certificate indices (comma-separated)")
        .int().split(",").default(emptyList(), defaultForHelp = "all certificates")
    private val timeout by option(help = "Server connection timeout; 0s for no timeout")
        .convert { Duration.parse(it) }.default(5.seconds)

    private val content = StringWriter()
    private val writer = PrintWriter(content)
    private val fingerprints = mutableSetOf<String>()

    @OptIn(ExperimentalSerializationApi::class)
    private val parser = Json {
        ignoreUnknownKeys = true
        prettyPrint = true
        prettyPrintIndent = "  "
    }

    override fun run() {
        when (inputFormat) {
            InputFormat.PEM, InputFormat.BASE64 -> handlePEM()
            InputFormat.SERVER -> handleServer()
            InputFormat.JSON -> handleJson()
            InputFormat.CONFIG -> handleConfig()
            InputFormat.VAULT -> handleVault()
        }
        writer.flush()

        val final = content.toString().let {
            when (outputFormat) {
                OutputFormat.BASE64, OutputFormat.CONFIG -> it.base64Encode()
                else -> it
            }
        }
        when {
            output == "-" -> println(final)
            outputFormat == OutputFormat.CONFIG -> updateConfig(final)
            else -> Path(output).writeText(final)
        }
    }

    private fun updateConfig(content: String) {
        val config = Path(output).readText()
        val configKey = getConfigKey()
        if (configKey.isNullOrBlank()) {
            info(input, "Key is required for config files")
            return
        }
        try {
            val json = parser.parseToJsonElement(config).jsonObject
            val updated = setJsonValue(json, "$configKey.tls.caBundleBase64", content)
            Path(output).writeText(parser.encodeToString(updated))
        } catch (e: Exception) {
            info(output, "Cannot parse as JSON")
            return
        }
    }


    private fun handlePEM() {
        if (input == "-") {
            val stdin = readText()
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
        handleServer(if (input == "-") readln() else input)
    }

    private fun handleServer(host: String) {
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

        // TODO: could not yet figure out how to combine timeout and cert extraction, so we currently
        // connect twice: first to make sure we can connect; and then to extract the certificates
        try {
            SSLSocketFactory.getDefault().createSocket().use {
                it.connect(InetSocketAddress(host, port), timeout.inWholeMilliseconds.toInt())
            }
        } catch (e: Exception) {
            info(host, "Could not connect within $timeout")
            return
        }

        val socketFactory = tlsContext.apply {
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

        val chain = tm.chain?.toMutableList()
        if (chain == null) {
            info(host, "Could not obtain server certificate chain")
            return
        }

        if (certIndex.isEmpty() || chain.size in certIndex) {
            val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
            trustManagerFactory.init(null as KeyStore?)
            val issuer = chain.last().issuerX500Principal
            val rootCertificate = trustManagerFactory.trustManagers
                .flatMap { t -> (t as X509TrustManager).acceptedIssuers.toList() }
                .find { it.issuerX500Principal == issuer }
            if (rootCertificate != null) {
                chain += rootCertificate
            }
        }

        process(host, chain)
    }

    private fun getConfigKey() = key.takeUnless { it.isNullOrBlank() }

    private fun handleJson() {
        val config = if (input == "-") readText() else Path(input).readText()
        val configKey = getConfigKey()
        if (configKey.isNullOrBlank()) {
            info(input, "Key is required for config files")
            return
        }

        var json: JsonElement? = parser.parseToJsonElement(config)
        for (comp in configKey.split(".")) {
            json = json?.jsonObject?.get(comp)
        }
        if (json == null) {
            info(input, "Cannot extract $configKey")
            return
        }

        if (hostName) {
            handleServer(json.jsonPrimitive.content)
        } else {
            chain(input, json.jsonPrimitive.content.base64Decode().inputStream())
        }
    }

    private fun handleConfig() {
        val config = if (input == "-") readText() else Path(input).readText()
        val configKey = getConfigKey()
        if (configKey.isNullOrBlank()) {
            info(input, "Key is required for config files")
            return
        }

        val json = parser.parseToJsonElement(config).jsonObject[configKey]
        if (json == null) {
            info(input, "Cannot extract $configKey")
            return
        }

        val partner = parser.decodeFromString<EAC>(parser.encodeToString(json))
        fingerprints += partner.tls.fingerprints256

        when {
            hostName -> handleServer(partner.tls.hostName)
            jwe -> chain(input, partner.api.JWEPublicKeyBase64.base64Decode().inputStream())
            else -> chain(input, partner.tls.caBundleBase64.base64Decode().inputStream())
        }
    }

    private fun getVaultKey(): String? {
        val configKey = key
        return when {
            configKey.isNullOrBlank() -> null
            "/quick-apply/" in configKey -> configKey
            else -> "/v1/secret/member/quick-apply/$configKey"
        }
    }

    private fun getEnv(name: String) = System.getenv(name).takeUnless { it.isNullOrBlank() }

    private fun getVaultHost(): String {
        return when {
            input != "-" -> input
            else -> getEnv("VAULT_ADDR") ?: VAULT_ADDR
        }
    }

    private fun getVaultToken(): String {
        return getEnv("VAULT_TOKEN") ?: Path(System.getenv("HOME"), ".vault-token").readText()
    }

    private fun handleVault() {
        val host = getVaultHost()
        val vaultKey = getVaultKey()
        if (vaultKey.isNullOrBlank()) {
            info(input, "Key is required for vault")
            return
        }
        val vaultToken = getVaultToken()
        if (vaultKey.isBlank()) {
            info(input, "Token is required for vault")
            return
        }

        val request = Request(Method.GET, Uri.of(host).appendToPath(vaultKey))
            .header("X-Vault-Token", vaultToken)
        // We currently have to use the insecure client because the vault certificate issuer is not in our
        // list of trusted root certificates
        val client = OkHttp(PreCannedOkHttpClients.insecureOkHttpClient())
        val response = client(request)
        if (response.status.code != 200) {
            info(input, "Vault did not return data")
            return
        }
        val json: JsonElement = parser.parseToJsonElement(response.bodyString())
        val data = json.jsonObject["data"]?.jsonObject?.get("value")?.jsonPrimitive?.content
        if (data == null) {
            info(input, "Vault did not return expected JSON")
            return
        }

        with(writer) {
            when (outputFormat) {
                OutputFormat.BASE64 -> println(data)
                OutputFormat.PEM -> println(data.base64Decode().decodeToString())
                else -> chain(input, data.base64Decode().inputStream())
            }
        }
    }

    private fun chain(name: String, inputStream: InputStream) {
        inputStream.use { stream ->
            try {
                process(name, certificateFactory.generateCertificates(stream).toList())
            } catch (e: Exception) {
                info(name, "Could not read as X509 certificate")
            }
        }
    }

    private fun readText() = generateSequence(::readLine).joinToString("\n")

    private fun info(name: String, info: String) {
        println("\n$name: $info")
    }

    private fun process(name: String, certificates: List<Certificate>) {
        for (cert in certificates.withIndex()) {
            if (certIndex.isEmpty() || cert.index in certIndex) {
                certificate(name, cert.value)
            }
        }

        if (!jwe && outputFormat == OutputFormat.SUMMARY && fingerprints.isNotEmpty()) {
            with(writer) {
                println("\nRemaining configured fingerprints:")
                for (fp in fingerprints) println("\t$fp")
            }
        }
    }

    private fun certificate(name: String, cert: Certificate) {
        when (outputFormat) {
            OutputFormat.SUMMARY -> certificateSummary(name, cert)
            OutputFormat.TEXT -> certificateText(name, cert)
            OutputFormat.BASE64, OutputFormat.PEM, OutputFormat.CONFIG -> certificatePem(cert)
        }
    }

    private fun certificateSummary(name: String, cert: Certificate) {
        fun altName(altName: List<*>, type: Int) = (altName[1] as String).takeIf { altName[0] as Int == type }

        fun dns(altNames: List<*>) = altName(altNames, 2)

        fun email(altNames: List<*>) = altName(altNames, 1)

        fun cn(principal: X500Principal) = principal.name.let { name ->
            LdapName(name).rdns.find { it.type == "CN" }?.value ?: name
        }

        fun fingerprint(data: ByteArray) = buildString {
            val fp = data.sha256Hex()
            append(fp)
            if (fingerprints.remove(fp)) append(" [on Record]")
        }

        fun keyUsage(data: BooleanArray) =
            data.mapIndexed { idx, b -> if (b && idx in keyUsages.indices) keyUsages[idx] else null }
                .filterNotNull().joinToString()

        fun extKeyUsage(data: List<String>) = data.joinToString { extendedKeyUsages[it] ?: "???" }

        try {
            with(writer) {
                with(cert as X509Certificate) {
                    println("\n$name: X509 v$version certificate for ${cn(subjectX500Principal)}")
                    println("\tCertificate fingerprint: ${fingerprint(encoded)}")
                    println("\tPublic key fingerprint: ${fingerprint(publicKey.encoded)}")
                    println("\tExpires: ${this.notAfter.toInstant()}")
                    println("\tIssuer: ${cn(issuerX500Principal)}")
                    // All the remaining properties can be `null`
                    if (keyUsage != null && keyUsage.isNotEmpty()) {
                        println("\tKey Usage: ${keyUsage(keyUsage)}")
                    }
                    if (extendedKeyUsage != null && extendedKeyUsage.isNotEmpty()) {
                        println("\tExtended Key Usage: ${extKeyUsage(extendedKeyUsage)}")
                    }
                    val dnsNames = subjectAlternativeNames?.mapNotNull { dns(it) }?.joinToString()
                    if (!dnsNames.isNullOrEmpty()) {
                        println("\tDNS names: $dnsNames")
                    }
                    val emails = subjectAlternativeNames?.mapNotNull { email(it) }?.joinToString()
                    if (!emails.isNullOrEmpty()) {
                        println("\tEmails: $emails")
                    }
                }
            }
        } catch (e: Exception) {
            info(name, "Could not read as X509 certificate")
        }
    }

    private fun certificateText(name: String, cert: Certificate) {
        with(writer) {
            println(name)
            println(cert)
        }
    }

    private fun certificatePem(cert: Certificate) {
        with(writer) {
            println("-----BEGIN CERTIFICATE-----")
            println(pemEncoder.encodeToString(cert.encoded))
            println("-----END CERTIFICATE-----")
        }
    }
}
