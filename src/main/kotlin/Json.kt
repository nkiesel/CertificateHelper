import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject

fun setJsonValue(json: JsonObject, path: String, value: String): JsonObject {
    return setJsonValue(json, path, JsonPrimitive(value))
}

fun setJsonValue(json: JsonObject, path: String, value: Int): JsonObject {
    return setJsonValue(json, path, JsonPrimitive(value))
}

private fun setJsonValue(obj: JsonObject, path: String, value: JsonPrimitive): JsonObject {
    return setJsonValueRec(obj, path.split("."), value)
}

private fun setJsonValueRec(obj: JsonObject, path: List<String>, value: JsonPrimitive): JsonObject =
    JsonObject(obj.toMutableMap().apply {
        val key = path.first()
        put(
            key,
            if (path.size == 1) {
                value
            } else {
                setJsonValueRec(get(key)!!.jsonObject, path.drop(1), value)
            }
        )
    }
    )
