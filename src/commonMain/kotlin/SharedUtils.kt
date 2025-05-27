package org.nkiesel.certificatehelper

/**
 * Shared utilities that can be used by both JVM and Native targets
 */
object SharedUtils {
    /**
     * Get the version of the application
     */
    fun getVersion(): String = "3.0.1"
    
    /**
     * Get the application name
     */
    fun getAppName(): String = "Certificate Helper"
    
    /**
     * Format a message with the application name and version
     */
    fun formatAppInfo(): String = "${getAppName()} v${getVersion()}"
}
