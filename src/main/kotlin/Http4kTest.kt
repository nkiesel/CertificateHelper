package nkiesel.org

import org.http4k.core.Method
import org.http4k.core.MultipartForm // The problematic import
import org.http4k.core.Request
import org.http4k.core.Response
import org.http4k.core.Status

fun main() { // A main function to make it runnable if needed, though compile-time check is key
    println("Http4k Test File: Attempting to reference Http4k types.")

    val request: Request? = Request(Method.GET, "/test")
    println("Request type resolved: ${request != null}")

    // Try to reference MultipartForm to see if it resolves at compile time
    val form: MultipartForm? = null
    // val formInstance = MultipartForm() // This would also test instantiation
    println("MultipartForm type resolved: ${form == null}") // Simple check that 'form' could be declared

    val response: Response? = Response(Status.OK)
    println("Response type resolved: ${response != null}")

    println("Http4k type resolution test complete.")
}
