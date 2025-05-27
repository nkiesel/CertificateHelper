import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.core.Context
import com.github.ajalt.clikt.core.main
import com.github.ajalt.mordant.terminal.Terminal
import org.nkiesel.certificatehelper.SharedUtils

fun main(args: Array<String>) {
    NativeCertificateHelper().main(args)
}

class NativeCertificateHelper : CliktCommand(name = "ch") {
    private val terminal = Terminal()

    override fun help(context: Context): String = """
    ${SharedUtils.getAppName()} (Native macOS ARM64 version)

    This is a simplified native version of the Certificate Helper tool.
    For full functionality, please use the JVM version.
    """.trimIndent()

    override fun run() {
        terminal.println("${SharedUtils.formatAppInfo()} - Native (macOS ARM64)")
        terminal.println("This is a simplified native version with limited functionality.")
        terminal.println("For full functionality, please use the JVM version.")
    }
}
