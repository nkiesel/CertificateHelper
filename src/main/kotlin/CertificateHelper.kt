import com.github.ajalt.clikt.completion.CompletionCandidates
import com.github.ajalt.clikt.completion.completionOption
import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.core.Context
import com.github.ajalt.clikt.core.installMordantMarkdown
import com.github.ajalt.clikt.core.main
import com.github.ajalt.clikt.parameters.arguments.argument
import com.github.ajalt.clikt.parameters.arguments.default
import com.github.ajalt.clikt.parameters.options.*
import com.github.ajalt.clikt.parameters.types.enum
import com.github.ajalt.clikt.parameters.types.int
import com.github.ajalt.mordant.rendering.TextColors.*
import com.github.ajalt.mordant.terminal.Terminal
import com.google.cloud.secretmanager.v1.ProjectName
import com.google.cloud.secretmanager.v1.SecretManagerServiceClient
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import org.http4k.client.OkHttp
import org.http4k.client.PreCannedOkHttpClients
import org.http4k.core.Method
import org.http4k.core.Request
import org.http4k.core.Uri
import org.http4k.core.appendToPath
import java.io.InputStream
import java.io.PrintWriter
import java.io.StringWriter
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.time.Instant
import java.util.*
import javax.naming.ldap.LdapName
import javax.net.ssl.*
import javax.security.auth.x500.X500Principal
import kotlin.io.path.*
import kotlin.system.exitProcess
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds


private val sha256 = MessageDigest.getInstance("SHA-256")
private val hexFormat = HexFormat.ofDelimiter("").withUpperCase()
private val certificateFactory = CertificateFactory.getInstance("X.509")
private val pemEncoder = Base64.getMimeEncoder(64, "\n".toByteArray())
private val tlsContext = SSLContext.getInstance("TLS")

fun ByteArray.sha256(): ByteArray = sha256.digest(this)
fun ByteArray.hex(): String = hexFormat.formatHex(this)
fun ByteArray.sha256Hex(): String = sha256().hex()
fun String.base64Decode(): ByteArray = Base64.getDecoder().decode(this.trim())
fun ByteArray.base64Encode(): String = Base64.getEncoder().encodeToString(this)
fun String.base64Encode(): String = encodeToByteArray().base64Encode()
fun ByteArray.fingerprint(): String = sha256Hex()


fun <T> List<T>?.hasContent() = !this.isNullOrEmpty()
fun String?.hasContent() = !this.isNullOrEmpty()
fun BooleanArray?.hasContent() = this != null && this.isNotEmpty()

enum class InputFormat {
    SERVER, JSON, PEM, BASE64, CONFIG, SECRET,
}

enum class OutputFormat {
    SUMMARY, TEXT, PEM, BASE64
}

private const val terminalIO = "-"

// https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.3
private val keyUsages = mapOf(
    0 to "Digital signature",
    1 to "content commitment",
    2 to "Key encipherment",
    3 to "Data encipherment",
    4 to "Key agreement",
    5 to "Certificate signing",
    6 to "CRL signing",
    7 to "Encipher only",
    8 to "Decipher only",
)

private class EKP(val name: String, val description: String) {
    fun toString(key: String, verbose: Boolean) = if (verbose) "$name: $description ($key)" else name
}

// https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.12
// name and description from https://oid-rep.orange-labs.fr/get/1.3.6.1.5.5.7.3 and https://www.rfc-editor.org/errata/eid5802
private val extendedKeyUsages = mapOf(
    "1.3.6.1.5.5.7.3.1" to EKP("serverAuth", "Transport Layer Security (TLS) server authentication"),
    "1.3.6.1.5.5.7.3.2" to EKP("clientAuth", "Transport Layer Security (TLS) client authentication"),
    "1.3.6.1.5.5.7.3.3" to EKP("codeSigning", "Signing of downloadable executable code"),
    "1.3.6.1.5.5.7.3.4" to EKP("emailProtection", "E-mail protection"),
    "1.3.6.1.5.5.7.3.5" to EKP("ipsecEndSystem", "Internet Protocol SECurity (IPSEC) end system certificate"),
    "1.3.6.1.5.5.7.3.6" to EKP("ipsecTunnel", "Internet Protocol SECurity (IPSEC) tunnel certificate"),
    "1.3.6.1.5.5.7.3.7" to EKP("ipsecUser", "Internet Protocol SECurity (IPSEC) user certificate"),
    "1.3.6.1.5.5.7.3.8" to EKP("timeStamping", "Binding the hash of an object to a time"),
    "1.3.6.1.5.5.7.3.9" to EKP("OCSPSigning", "Signing Online Certificate Status Protocol (OCSP) responses"),
    "1.3.6.1.5.5.7.3.21" to EKP("secureShellClient", "Key can be used for a Secure Shell client"),
    "1.3.6.1.5.5.7.3.22" to EKP("secureShellServer", "Key can be used for a Secure Shell server"),
    "1.3.6.1.5.5.7.3.33" to EKP("rpcTLSClient", "id-kp-rpcTLSClient"),
    "1.3.6.1.5.5.7.3.34" to EKP("rpcTLSServer", "id-kp-rpcTLSServer"),
    "1.3.6.1.5.5.7.3.36" to EKP("documentSigning", "Extended key purpose for document signing in certificates"),
    "1.3.6.1.5.5.7.3.37" to EKP("jwt", "id-kp-jwt"),
    "1.3.6.1.5.5.7.3.38" to EKP("httpContentEncrypt", "id-kp-httpContentEncrypt"),
    "1.3.6.1.5.5.7.3.39" to EKP("oauthAccessTokenSigning", "id-kp-oauthAccessTokenSigning"),
    // https://access.redhat.com/documentation/en-us/red_hat_certificate_system/9/html/administration_guide/standard_x.509_v3_certificate_extensions#Discussion-PKIX_Extended_Key_Usage_Extension_Uses
    "1.3.6.1.4.1.311.10.3.1" to EKP("CTLSigning", "Certificate trust list signing"),
    "1.3.6.1.4.1.311.10.3.3" to EKP("SGC", "Microsoft Server Gated Crypto (SGC)"),
    "1.3.6.1.4.1.311.10.3.4" to EKP("EFS", "Microsoft Encrypted File System"),
    // https://www.pkisolutions.com/object-identifiers-oid-in-pki/
    "1.3.6.1.4.1.311.10.3.12" to EKP("DocSigning", "Microsoft Document Signing"),
    "1.3.6.1.4.1.311.20.2.2" to EKP("SmartCard", "Microsoft Smart Card Logon"),
    "2.16.840.1.113730.4.1" to EKP("export-approved", "Netscape Server Gated Crypto (SGC)"),
    "1.2.840.113583.1.1.5" to EKP("AADT", "Adobe Authentic Documents Trust"),
)

typealias X509List = List<X509Certificate>

fun main(args: Array<String>) {
    CertificateHelper().run {
        installMordantMarkdown()
        main(args)
    }
}

class CertificateHelper : CliktCommand(name = "ch") {
    init {
        completionOption()
        versionOption(
            javaClass.getResourceAsStream("version")?.bufferedReader()?.use { it.readLine() } ?: "development",
            names = setOf("--version")
        )
    }

    override fun help(context: Context): String = """
    Reads or updates certificates from server, config, file, or secret.  Examples:
    ```
    ch -f server api.github.com
    ch -f pem my_cert.pem
    ```
    """.trimIndent()

    override fun helpEpilog(context: Context): String = """
    GSM operations need an access token. Run `gcloud auth application-default login`
    to allow `ch` access to GSM.
    """.trimIndent()

    private val inputOption by option(
        "-i", "--input", completionCandidates = CompletionCandidates.Path,
        help = "Input file or server name; - for stdin"
    ).default("-")
    private val inputFormat by option("-f", "--inputFormat", help = "Input format").enum<InputFormat>()
        .default(InputFormat.CONFIG)
    private val hostName by option("-n", "--hostName", help = "CA bundle using partner server name from config").flag()
    private val jwe by option("-j", "--jwe", help = "partner JWE info from config").flag()
    private val tls by option("--tls", help = "own TLS info from config").flag()
    private val bundle by option("-b", "--bundle", help = "partner CA bundle info from config").flag(default = false)
    private val key by option("-k", "--key", help = "partner config key")
    private val secretName by option("-s", "--secretName", help = "partner-related secret name").default("")
    private val port by option("-p", "--port", help = "partner server port").int().default(443)
    private val output by option(
        "-o", "--output", completionCandidates = CompletionCandidates.Path,
        help = "Output file name; - for stdout"
    ).default(terminalIO)
    private val outputFormat by option("-t", "--outputFormat", help = "Output format").enum<OutputFormat>()
        .default(OutputFormat.SUMMARY)
    private val certIndex: List<Int> by option("-c", "--certIndex", help = "Certificate indices (comma-separated)")
        .int().split(",").default(emptyList(), defaultForHelp = "all certificates")
    private val timeout by option(help = "Server connection timeout; 0s for no timeout")
        .convert { Duration.parse(it) }.default(5.seconds)
    private val rootCAs by option("--rootCAs", help = "list root CAs, filter with optional regex").optionalValue(".*")
    private val verbose by option("-v", "--verbose", help = "more verbose output").flag()
    private val inputArgument by argument("input", help = "Input file or server name; - for stdin").default("")
    private lateinit var input: String
    private var useStdin: Boolean = true

    private val content = StringWriter()
    private val writer = PrintWriter(content)
    private val rootCertificates = getRootCertificates()
    private val terminal = Terminal()

    private fun getRootCertificates(): Map<X500Principal, X509Certificate> {
        val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        trustManagerFactory.init(null as KeyStore?)
        return trustManagerFactory.trustManagers
            .flatMap { t -> (t as X509TrustManager).acceptedIssuers.toList() }
            .associateBy { it.subjectX500Principal }
    }

    @OptIn(ExperimentalSerializationApi::class)
    private val parser = Json {
        ignoreUnknownKeys = true
        prettyPrint = true
        prettyPrintIndent = "  "
    }

    override fun run() {
        val pattern = rootCAs?.toRegex()
        if (pattern != null) {
            for (cert in rootCertificates.filter { it.key.toString().contains(pattern) }) {
                certificateSummary(cert.value)
            }
            writer.flush()
            print(content.toString())
            exitProcess(0)
        }

        input = inputArgument.ifBlank { inputOption }
        useStdin = input == terminalIO

        when (if (secretName.isNotBlank()) InputFormat.SECRET else inputFormat) {
            InputFormat.PEM, InputFormat.BASE64 -> handlePEM()
            InputFormat.SERVER -> handleServer()
            InputFormat.JSON -> handleJson()
            InputFormat.CONFIG -> handleConfig()
            InputFormat.SECRET -> handleSecret()
        }
        writer.flush()

        val final = content.toString().let {
            when (outputFormat) {
                OutputFormat.BASE64 -> it.base64Encode()
                else -> it
            }
        }
        when {
            output == terminalIO -> terminal.print(final)
            else -> Path(output).writeText(final)
        }
    }

    private fun handlePEM() {
        if (useStdin) {
            val text = readText()
            val inputStream = when (inputFormat) {
                InputFormat.BASE64 -> text.base64Decode().inputStream()
                else -> text.byteInputStream()
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
        handleServer(if (useStdin) readln() else input)
    }

    private fun getChain(host: String, address: InetAddress): X509List {
        val tm = object : X509TrustManager {
            var chain: X509List? = null

            override fun getAcceptedIssuers(): Array<X509Certificate> {
                throw UnsupportedOperationException()
            }

            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {
                throw UnsupportedOperationException()
            }

            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
                this.chain = chain.toList()
            }
        }

        // TODO: could not yet figure out how to combine timeout and cert extraction, so we currently
        //  connect twice: first to make sure we can connect; and then to extract the certificates
        try {
            SSLSocketFactory.getDefault().createSocket().use {
                it.connect(InetSocketAddress(address, port), timeout.inWholeMilliseconds.toInt())
            }
        } catch (_: Exception) {
            error(host, "Could not connect to $address within $timeout")
        }

        val socketFactory = tlsContext.apply {
            init(null, arrayOf<X509TrustManager>(tm), null)
        }.socketFactory

        val sslSocket = try {
            socketFactory.createSocket(address, port) as SSLSocket
        } catch (_: Exception) {
            error(host, "Could not connect to $address")
        }
        sslSocket.use {
            try {
                it.startHandshake()
            } catch (_: SSLException) {
            }
        }

        val chain = tm.chain?.toMutableList() ?: error(host, "Could not obtain server certificate chain for $address")

        if (considerCertificate(chain.size)) {
            do {
                val last = chain.last()
                val issuer = last.issuerX500Principal
                val rootCertificate = rootCertificates[issuer]
                // Add the root certificate unless the current root is already self-signed
                if (rootCertificate == null || issuer == last.subjectX500Principal) {
                    break
                }
                chain += rootCertificate
            } while (true)
        }

        return chain
    }

    private fun considerCertificate(idx: Int) = certIndex.isEmpty() || idx in certIndex

    private fun handleServer(host: String) {
        val addresses = InetAddress.getAllByName(host).filterIsInstance<Inet4Address>()
        val count = addresses.size
        if (outputFormat == OutputFormat.SUMMARY || outputFormat == OutputFormat.TEXT) {
            info(host, "Addresses: ${addresses.map { it.hostAddress }}")
        }

        val chains = addresses.map { getChain(host, it) }
        if (chains.any { it.isEmpty() }) {
            info(host, "Could not get certificate chains for all addresses")
        } else if (count == 1 || chains.map { it[0].encoded.sha256Hex() }.distinct().size == 1) {
            process(host, chains.first())
        } else {
            info(host, "Different certificates for different addresses")
            if (outputFormat == OutputFormat.SUMMARY || outputFormat == OutputFormat.TEXT) {
                addresses.forEachIndexed { i, a -> process(a.hostAddress, chains[i]) }
            }
        }
    }

    private fun getConfigKey() = key.takeUnless { it.isNullOrBlank() }

    private fun handleJson() {
        val configKey = getConfigKey()
        if (configKey.isNullOrBlank()) {
            error(input, "Key is required for config files")
        }

        val config = if (useStdin) readText() else Path(input).readText()
        var json: JsonElement? = parser.parseToJsonElement(config)
        val arrayRegex = Regex("""(.+)\[(\d+)]""")
        for (comp in configKey.split(".")) {
            val array = arrayRegex.matchEntire(comp)
            json = if (array !== null) {
                val (name, index) = array.destructured
                json?.jsonObject?.get(name)?.jsonArray?.get(index.toInt())
            } else {
                json?.jsonObject?.get(comp)
            }
        }
        if (json == null) {
            error(input, "Cannot extract $configKey")
        }

        if (hostName) {
            handleServer(json.jsonPrimitive.content)
        } else {
            chain(input, json.jsonPrimitive.content.base64Decode().inputStream())
        }
    }

    private inner class Config(config: String) {
        val jsonElement = parser.parseToJsonElement(config)

        inline fun <reified T> extract(name: String): T {
            try {
                return parser.decodeFromString<T>(parser.encodeToString(jsonElement.jsonObject[name]))
            } catch (_: Exception) {
                error(input, "Cannot extract $name")
            }
        }
    }

    private fun handleConfig() {
        val configKey = getConfigKey()
        if (configKey.isNullOrBlank()) {
            error(input, "Key is required for config files")
        }
        val config = Config(if (useStdin) readText() else Path(input).readText())
        val gcpSecretManager = config.extract<GCPSecretManager>("gcp-secret-manager")
        val projectName = ProjectName.of(gcpSecretManager.project)
        val partner = config.extract<EAC>(configKey)
        when {
            hostName -> handleServer(partner.tls.hostName)
            jwe || tls -> secrets(
                projectName,
                if (jwe) partner.api?.partnerJWECertificates else partner.tls.ckTLSCertificates
            )?.forEach { (name, value) ->
                chain(
                    "$name from $projectName",
                    value.base64Decode().inputStream()
                )
            }
            bundle -> chain(input, partner.tls.caBundleBase64?.base64Decode()?.inputStream())
        }
    }

    fun PartnerRelatedSecret(key: String) = PartnerRelatedSecret(
        current = GSMReference("user", key),
        next = GSMReference("user", key)
    )

    private fun handleSecret() {
        if (secretName.isBlank()) {
            error(input, "Secret name is required")
        }

        val config = Config(if (useStdin) readText() else Path(input).readText())
        val gcpSecretManager = config.extract<GCPSecretManager>("gcp-secret-manager")
        val projectName = ProjectName.of(gcpSecretManager.project)
        secrets(projectName, PartnerRelatedSecret(secretName))?.forEach { (name, value) ->
            chain(
                "$name from $projectName",
                value.base64Decode().inputStream()
            )
        }
    }

    private fun secrets(projectName: ProjectName, partnerRelatedSecret: PartnerRelatedSecret?): Map<String, String>? {
        if (partnerRelatedSecret == null) {
            return null
        }
        try {
            SecretManagerServiceClient.create().use { client ->
                fun value(secret: GSMReference): Pair<String, String> =
                    secret.key to (client.accessSecretVersion(secret.latest(projectName)).payload.data.toString(Charsets.US_ASCII)
                        ?: "")

                val current = value(partnerRelatedSecret.current)
                if (partnerRelatedSecret.current.key == partnerRelatedSecret.next.key) {
                    return mapOf(current)
                } else {
                    val next = value(partnerRelatedSecret.next)
                    return if (current.second == next.second) {
                        mapOf("${current.first} and ${next.first}" to current.second)
                    } else {
                        mapOf(current, next)
                    }
                }
            }
        } catch (e: Exception) {
            error(input, "Could not read secrets from ${projectName.project}: ${e.message?.lines()?.get(0)}")
        }
    }

    private fun chain(name: String, inputStream: InputStream?) {
        if (inputStream == null) {
            error(name, "No data")
        }
        inputStream.use { stream ->
            try {
                process(name, certificateFactory.generateCertificates(stream).map { it as X509Certificate })
            } catch (_: Exception) {
                error(name, "Could not read as X509 certificate")
            }
        }
    }

    private fun readText() = generateSequence(::readLine).joinToString("\n")

    private fun info(name: String, info: String) {
        terminal.println("\n$name: $info")
    }

    private fun error(name: String, info: String): Nothing {
        info(name, red(info))
        exitProcess(1)
    }

    private fun process(name: String, certificates: X509List) {
        for (cert in certificates.withIndex()) {
            if (considerCertificate(cert.index)) {
                certificate(cert.value, name)
            }
        }
    }

    private fun certificate(cert: X509Certificate, name: String) {
        when (outputFormat) {
            OutputFormat.SUMMARY -> certificateSummary(cert, name)
            OutputFormat.TEXT -> certificateText(cert, name)
            OutputFormat.BASE64, OutputFormat.PEM -> certificatePem(cert)
        }
    }

    private fun certificateSummary(cert: X509Certificate, name: String? = null) {
        fun altName(altName: List<*>, type: Int) = (altName[1] as String).takeIf { altName[0] as Int == type }

        fun dns(altNames: List<*>) = altName(altNames, 2)

        fun email(altNames: List<*>) = altName(altNames, 1)

        fun cn(principal: X500Principal) = principal.name.let { name ->
            LdapName(name).rdns.find { it.type == "CN" }?.value ?: name
        }

        fun keyUsage(data: BooleanArray) =
            data.mapIndexed { idx, b -> if (b) keyUsages[idx] ?: "bit $idx set to true" else null }
                .filterNotNull().joinToString()

        fun extKeyUsage(data: List<String>): String {
            val transform: (String) -> String = { extendedKeyUsages[it]?.toString(it, verbose) ?: it }
            return if (verbose) {
                val separator = "\n\t\t"
                data.joinToString(separator, prefix = separator, transform = transform)
            } else {
                data.joinToString(transform = transform)
            }
        }

        with(writer) {
            with(cert) {
                val rootCA = rootCertificates[subjectX500Principal]
                val fingerprint = encoded.fingerprint()
                val root = when {
                    rootCA == null -> ""
                    rootCA.encoded.fingerprint() == fingerprint -> "${green("trusted")} root "
                    else -> "${red("untrusted")} root "
                }
                val selfSigned = if (subjectX500Principal == issuerX500Principal) "self-signed " else ""
                val prefix = if (name.isNullOrEmpty()) "" else "$name: "
                println("\n${prefix}X509 v$version ${selfSigned}${root}certificate for ${cn(subjectX500Principal)}")
                println("\tCertificate fingerprint: $fingerprint")
                println("\tPublic key fingerprint: ${publicKey.encoded.fingerprint()}")
                if (verbose) println("\tSerial number: $serialNumber")
                val now = Instant.now()
                val notBeforeInstant = notBefore.toInstant()
                if (notBeforeInstant > now) {
                    println("\tNot Before: ${yellow(notBeforeInstant.toString())}")
                }
                val notAfterInstant = notAfter.toInstant()
                if (notAfterInstant < now) {
                    println("\tExpires: ${yellow(notAfterInstant.toString())}")
                } else {
                    println("\tExpires: $notAfterInstant")
                }
                println("\tIssuer: ${cn(issuerX500Principal)}")
                // All the remaining properties can be `null`
                if (keyUsage.hasContent()) {
                    println("\tKey Usage: ${keyUsage(keyUsage)}")
                }
                if (extendedKeyUsage.hasContent()) {
                    println("\tExtended Key Usage: ${extKeyUsage(extendedKeyUsage)}")
                }
                val dnsNames = subjectAlternativeNames?.mapNotNull { dns(it) }?.joinToString()
                if (dnsNames.hasContent()) {
                    println("\tDNS names: $dnsNames")
                }
                val emails = subjectAlternativeNames?.mapNotNull { email(it) }?.joinToString()
                if (emails.hasContent()) {
                    println("\tEmails: $emails")
                }
            }
        }
    }

    private fun certificateText(cert: X509Certificate, name: String) {
        with(writer) {
            println(name)
            println(cert)
        }
    }

    private fun certificatePem(cert: X509Certificate) {
        with(writer) {
            println("-----BEGIN CERTIFICATE-----")
            println(pemEncoder.encodeToString(cert.encoded))
            println("-----END CERTIFICATE-----")
        }
    }
}
