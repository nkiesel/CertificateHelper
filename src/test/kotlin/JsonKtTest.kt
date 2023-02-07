import io.kotest.matchers.shouldBe
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Test

class JsonKtTest {
    @Test
    fun updateSimple() {
        val source = """
            {
              "name": "Mary Poppins",
              "age": 23
            }
        """.trimIndent()
        val json = Json.parseToJsonElement(source).jsonObject
        val updated = setJsonValue(json, "age", 45)
        updated["age"]!!.jsonPrimitive.int shouldBe 45
    }

    @Test
    fun updateNested() {
        val source = """
            {
              "name": "Mary Poppins",
              "age": 23,
              "book": {
                "language": "French"
              }
            }
        """.trimIndent()
        val json = Json.parseToJsonElement(source).jsonObject
        val updated = setJsonValue(json, "book.language", "English")
        updated["book"]!!.jsonObject["language"]!!.jsonPrimitive.content shouldBe "English"
    }
}
