import io.kotest.matchers.shouldBe
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json
import org.junit.jupiter.api.Test

class EACTest {
    private val json = """
   {
    "api": {
      "JWEPublicKeyBase64": ["abcde"],
      "timeoutInMs": 60000
    },
    "tls": {
      "hostName": "api.example.com",
      "caBundleBase64": "abcde"
    }
  }
    """.trimIndent()

    @Test
    fun `parse Json`() {
        val eac = Json { ignoreUnknownKeys = true }.decodeFromString<EAC>(json)
        eac.tls.hostName shouldBe "api.example.com"
    }
}
