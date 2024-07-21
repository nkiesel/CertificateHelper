import io.kotest.matchers.shouldBe
import kotlinx.serialization.json.Json
import org.intellij.lang.annotations.Language
import org.junit.jupiter.api.Test

class EACTest {
    private val json = Json { ignoreUnknownKeys = true }

    @Language("JSON")
    private val abc = """
   {
    "tls": {
      "hostName": "api.example.com",
      "ckTLSCertificates": {
      "current": {
         "_source": "vault",
      "_key": "abc-tls-ck-certificate-current"
      },
      "next": {
      "_source": "vault",
      "_key": "abc-tls-ck-certificate-next"
      } 
      },
      "ckTLSPrivateKeys": {
      "current": {
         "_source": "vault",
      "_key": "abc-tls-ck-privatekey-current"
      },
      "next": {
      "_source": "vault",
      "_key": "abc-tls-ck-privatekey-next"
      } 
      }
    }
  }
    """.trimIndent()

    @Test
    fun `parse Json`() {
        val eac = json.decodeFromString<EAC>(abc)
        eac.tls.hostName shouldBe "api.example.com"
        eac.tls.ckTLSCertificates.current.key shouldBe "abc-tls-ck-certificate-current"
    }
}
