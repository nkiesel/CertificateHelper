import com.github.ajalt.clikt.completion.CompletionCandidates
import com.github.ajalt.clikt.completion.completionOption
import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.core.context
import com.github.ajalt.clikt.output.CliktHelpFormatter
import com.github.ajalt.clikt.parameters.options.*
import com.github.ajalt.clikt.parameters.types.enum
import com.github.ajalt.clikt.parameters.types.int
import kotlinx.serialization.ExperimentalSerializationApi
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
import java.io.InputStream
import java.io.PrintWriter
import java.io.StringWriter
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

fun <T> List<T>?.hasContent() = !this.isNullOrEmpty()
fun String?.hasContent() = !this.isNullOrEmpty()
fun BooleanArray?.hasContent() = this != null && this.isNotEmpty()

enum class InputFormat {
    SERVER, JSON, PEM, BASE64, VAULT, CONFIG
}

enum class OutputFormat {
    SUMMARY, TEXT, PEM, BASE64, CONFIG
}

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

typealias X509List = List<X509Certificate>

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
        versionOption(
            javaClass.getResourceAsStream("version")?.bufferedReader()?.use { it.readLine() } ?: "development",
            names = setOf("-v", "--version")
        )
    }

    private val input by option(
        "-i", "--input", completionCandidates = CompletionCandidates.Path,
        help = "Input file or server name; - for stdin"
    ).default("-")
    private val inputFormat by option("-f", "--inputFormat", help = "Input format").enum<InputFormat>()
        .default(InputFormat.CONFIG)
    private val hostName by option("-n", "--hostName", help = "CA bundle using server name from config").flag()
    private val jwe by option("-j", "--jwe", help = "JWE info from config").flag()
    private val bundle by option("-b", "--bundle", help = "CA bundle info from config").flag(default = true)
    private val key by option("-k", "--key", help = "Config key")
    private val cleanup by option("--cleanup", help = "Clean up certificates (remove duplicates, drop expired)").flag()
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
    private val configuredFingerprints = mutableSetOf<String>()
    private val seenFingerprints = mutableSetOf<String>()
    private val rootCertificates = getRootCertificates()

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
            output == "-" -> print(final)
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
        // connect twice: first to make sure we can connect; and then to extract the certificates
        try {
            SSLSocketFactory.getDefault().createSocket().use {
                it.connect(InetSocketAddress(address, port), timeout.inWholeMilliseconds.toInt())
            }
        } catch (e: Exception) {
            info(host, "Could not connect to $address within $timeout")
            return emptyList()
        }

        val kmf: KeyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply {
            init(null, "".toCharArray())
        }
        val socketFactory = tlsContext.apply {
            init(null, arrayOf<X509TrustManager>(tm), null)
        }.socketFactory

        val sslSocket = try {
            socketFactory.createSocket(address, port) as SSLSocket
        } catch (e: Exception) {
            info(host, "Could not connect to $address")
            return emptyList()
        }
        sslSocket.use {
            try {
                it.startHandshake()
            } catch (_: SSLException) {
            }
        }

        val chain = tm.chain?.toMutableList()
        if (chain == null) {
            info(host, "Could not obtain server certificate chain for $address")
            return emptyList()
        }

        if (certIndex.isEmpty() || chain.size in certIndex) {
            do {
                val last = chain.last()
                val issuer = last.issuerX500Principal
                // Try to add the root certificate unless the current root is already self-signed
                val rootCertificate = rootCertificates[issuer]
                if (rootCertificate == null || issuer == last.subjectX500Principal) {
                    break
                }
                chain += rootCertificate
            } while (true)
        }

        return chain
    }

    private fun handleServer(host: String) {
        val addresses = InetAddress.getAllByName(host)
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
        partner.tls.fingerprints256?.let { configuredFingerprints += it }

        when {
            hostName -> handleServer(partner.tls.hostName)
            jwe -> chain(input, partner.api?.JWEPublicKeyBase64?.base64Decode()?.inputStream())
            bundle -> chain(input, partner.tls.caBundleBase64?.base64Decode()?.inputStream())
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
            else -> getEnv("VAULT_ADDR") ?: ""
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
        if (vaultToken.isBlank()) {
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

    private fun chain(name: String, inputStream: InputStream?) {
        if (inputStream == null) {
            info(name, "No data")
            return
        }
        inputStream.use { stream ->
            try {
                process(name, certificateFactory.generateCertificates(stream).map { it as X509Certificate })
            } catch (e: Exception) {
                info(name, "Could not read as X509 certificate")
            }
        }
    }

    private fun readText() = generateSequence(::readLine).joinToString("\n")

    private fun info(name: String, info: String) {
        println("\n$name: $info")
    }

    /**
     * This removes duplicates and expired certificates from the list. It also sorts the certificates
     * so that issuers of a certificate - if they are part of the list - come after the certificate.
     */
    private fun cleanup(list: X509List): X509List {
        /**
         *  Split the [candidates] into 2 lists: those who have an issuer in the [parents] list, and the rest
         */
        fun findChildren(parents: X509List, candidates: X509List): Pair<X509List, X509List> {
            val parentIds = parents.map { it.subjectX500Principal }
            return candidates.partition { it.issuerX500Principal in parentIds }
        }

        // Filter and sort and split into root certs and the rest
        val now = Instant.now()
        var (issuers, candidates) = list
            .filter { it.notAfter.toInstant() >= now }
            .distinctBy { it.subjectX500Principal }
            .sortedBy { cert -> cert.notAfter }
            .partition { it.subjectX500Principal == it.issuerX500Principal }

        // Add immediate children of issuers to issuers
        while (candidates.isNotEmpty()) {
            findChildren(issuers, candidates).let { (children, remaining) ->
                if (children.isEmpty()) {
                    // could not find any cert in candidates issued by issuer
                    issuers += remaining
                    candidates = emptyList()
                } else {
                    issuers += children
                    candidates = remaining
                }
            }
        }

        // We want the leaf certs first, so reversing the list
        return issuers.reversed()
    }

    private fun process(name: String, certificates: X509List) {
        val certs = if (cleanup) cleanup(certificates) else certificates
        for (cert in certs.withIndex()) {
            if (certIndex.isEmpty() || cert.index in certIndex) {
                certificate(name, cert.value)
            }
        }

        if (!jwe && outputFormat == OutputFormat.SUMMARY) {
            val unseenFingerprints = configuredFingerprints - seenFingerprints
            if (unseenFingerprints.isNotEmpty()) {
                with(writer) {
                    println("\nRemaining configured fingerprints:")
                    for (fp in unseenFingerprints) println("\t$fp")
                }
            }
        }
    }

    private fun certificate(name: String, cert: X509Certificate) {
        when (outputFormat) {
            OutputFormat.SUMMARY -> certificateSummary(name, cert)
            OutputFormat.TEXT -> certificateText(name, cert)
            OutputFormat.BASE64, OutputFormat.PEM, OutputFormat.CONFIG -> certificatePem(cert)
        }
    }

    private fun certificateSummary(name: String, cert: X509Certificate) {
        fun altName(altName: List<*>, type: Int) = (altName[1] as String).takeIf { altName[0] as Int == type }

        fun dns(altNames: List<*>) = altName(altNames, 2)

        fun email(altNames: List<*>) = altName(altNames, 1)

        fun cn(principal: X500Principal) = principal.name.let { name ->
            LdapName(name).rdns.find { it.type == "CN" }?.value ?: name
        }

        fun fingerprint(data: ByteArray) = buildString {
            val fp = data.sha256Hex()
            append(fp)
            if (fp in configuredFingerprints) append(" [on Record]")
            seenFingerprints += fp
        }

        fun keyUsage(data: BooleanArray) =
            data.mapIndexed { idx, b -> if (b && idx in keyUsages.indices) keyUsages[idx] else null }
                .filterNotNull().joinToString()

        fun extKeyUsage(data: List<String>) = data.joinToString { extendedKeyUsages[it] ?: "???" }

        with(writer) {
            with(cert) {
                val root = if (rootCertificates.containsKey(subjectX500Principal)) "trusted root " else ""
                val selfSigned = if (subjectX500Principal == issuerX500Principal) "self-signed " else ""
                println("\n$name: X509 v$version ${selfSigned}${root}certificate for ${cn(subjectX500Principal)}")
                println("\tCertificate fingerprint: ${fingerprint(encoded)}")
                println("\tPublic key fingerprint: ${fingerprint(publicKey.encoded)}")
                val notBeforeInstant = notBefore.toInstant()
                if (notBeforeInstant > Instant.now()) {
                    println("\tNot Before: $notBeforeInstant")
                }
                println("\tExpires: ${notAfter.toInstant()}")
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

    private fun certificateText(name: String, cert: X509Certificate) {
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
