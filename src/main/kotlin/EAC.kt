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
    val JWEPublicKeyBase64: String,
    val JWEPrivateKeyBase64: JWEPrivateKeyBase64,
//    val timeoutInMs: Int
)

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
    val caBundleBase64: String? = null,
    val fingerprints256: List<String>? = null,
//    val clientCertificateBase64: String,
//    val clientPrivateKeyBase64: ClientPrivateKeyBase64
)

//@Serializable
//data class ClientPrivateKeyBase64(
//    val _source: String,
//    val _key: String
//)
