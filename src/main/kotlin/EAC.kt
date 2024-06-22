import kotlinx.serialization.Serializable

@Serializable
data class EAC(
    val api: Api? = null,
//    val continueUrl: String,
//    val secondsBetweenHealthchecks: Int,
//    val statusPageUrlTemplate: String,
//    val tilaUrl: String,
    val tls: Tls
)

@Serializable
data class Api(
    val JWEPublicKeyBase64: Array<String>,
//    val JWEPrivateKeyBase64: Array<JWEPrivateKeyBase64>,
//    val timeoutInMs: Int
) {
    override fun equals(other: Any?): Boolean {
        return this === other || other is Api && JWEPublicKeyBase64.contentEquals(other.JWEPublicKeyBase64)
    }

    override fun hashCode(): Int {
        return JWEPublicKeyBase64.contentHashCode()
    }
}

@Serializable
data class JWEPrivateKeyBase64(
    val _source: String,
    val _key: String
)

@Serializable
data class Tls(
    val hostName: String,
//    val hostHeader: String,
//    val path: String,
//    val healthCheckPath: String,
//    val ciphers: String,
    val overrideBundle: Boolean = false,
    val caBundleBase64: String? = null,
    val clientCertificateBase64: String? = null,
//    val clientPrivateKeyBase64: ClientPrivateKeyBase64
)

//@Serializable
//data class ClientPrivateKeyBase64(
//    val _source: String,
//    val _key: String
//)
