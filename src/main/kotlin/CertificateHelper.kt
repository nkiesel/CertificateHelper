package nkiesel.org

import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.core.subcommands
// import com.github.ajalt.clikt.core.Context // Only needed if currentContext is used in run()

// --- Most top-level declarations are commented out ---
// import java.security.MessageDigest
// import java.security.cert.CertificateFactory
// import java.util.Base64
// import javax.net.ssl.SSLContext
// import java.util.HexFormat // Requires Java 17+ or Android API 33+

// private val sha256 = MessageDigest.getInstance("SHA-256")
// private val hexFormat = HexFormat.ofDelimiter("").withUpperCase()
// private val certificateFactory = CertificateFactory.getInstance("X.509")
// private val pemEncoder = Base64.getMimeEncoder(64, "\n".toByteArray())
// private val tlsContext = SSLContext.getInstance("TLS")

class CertificateHelperException(message: String) : RuntimeException(message)

// --- All extension functions commented out ---
// fun ByteArray.sha256(): ByteArray = ...
// fun ByteArray.hex(): String = ...
// ... etc. ...

// --- All enums, consts, maps, typealiases, data classes (like EKP) commented out ---
// enum class InputFormat { ... }
// enum class OutputFormat { ... }
// private const val terminalIO = "-"
// private val keyUsages = mapOf<Int, String>(...)
// private class EKP(val name: String, val description: String) { ... }
// private val extendedKeyUsages = mapOf<String, EKP>(...)
// typealias X509List = List<X509Certificate>


fun main(args: Array<String>) = CertificateHelper().main(args)

class ServeWeb : CliktCommand(name = "serve", help = "Start the web server interface") {
    override fun run() {
        // nkiesel.org.WebServer().start() // Keep this commented out for now
        println("Minimal ServeWeb executed") // For testing
    }
}

class CertificateHelper : CliktCommand(name = "ch") {
    init {
        subcommands(ServeWeb())
        // Ensure other init block items like installMordantMarkdown, etc., remain commented or removed.
    }
    override fun run() {
        // This is the required run method.
        // currentContext.terminal.println("Minimal CertificateHelper executed") // For testing
    }

    // --- All properties, original run() content, and helper methods are commented out ---
    // override fun help(context: Context): String = "Minimal help."
    // override fun helpEpilog(context: Context): String = "Minimal epilog."
    // ... (all Clikt options, arguments, internal state variables) ...
    // ... (original override fun run() body) ...
    // ... (all private helper methods, public PartnerRelatedSecret constructor) ...
}
