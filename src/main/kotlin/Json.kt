import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject

fun setJsonValue(json: JsonObject, path: String, value: String): JsonObject {
    return setJsonValueRec(json, path.split("."), JsonPrimitive(value))
}

fun setJsonValue(json: JsonObject, path: String, value: Int): JsonObject {
    return setJsonValueRec(json, path.split("."), JsonPrimitive(value))
}

fun setJsonValue(json: JsonObject, path: String, value: Boolean): JsonObject {
    return setJsonValueRec(json, path.split("."), JsonPrimitive(value))
}

private tailrec fun setJsonValueRec(obj: JsonObject, path: List<String>, value: JsonPrimitive): JsonObject {
    return JsonObject(obj.toMutableMap().apply {
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
}
