import com.google.cloud.secretmanager.v1.ProjectName
import com.google.cloud.secretmanager.v1.SecretVersionName
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class EAC(
    val oauth: OAuth? = null,
    val tls: Tls,
    val api: Api? = null
)

@Serializable
data class GCPSecretManager(
    val enabled: Boolean,
    val project: String
)

@Serializable
data class GSMReference(
    @SerialName("_source") val source: String,
    @SerialName("_key") val key: String,
    ) {
    fun latest(project: ProjectName): SecretVersionName = SecretVersionName.of(project.project, source, "latest")
}

@Serializable
data class PartnerRelatedSecret(
    val current: GSMReference,
    val next: GSMReference,
)

@Serializable
data class Api(
    val partnerJWECertificates: PartnerRelatedSecret,
    val ckJWEPrivateKeys: PartnerRelatedSecret,
)

@Serializable
data class Tls(
    val hostName: String,
    val overrideBundle: Boolean = false,
    val caBundleBase64: String? = null,
    val clientCertificateBase64: String? = null,
    val ckTLSCertificates: PartnerRelatedSecret,
    val ckTLSPrivateKeys: PartnerRelatedSecret,
)

@Serializable
data class OAuthClientConfig(
    @SerialName("client_id") val clientId: GSMReference,
    @SerialName("client_secrets") val clientSecrets: PartnerRelatedSecret,
)

@Serializable
data class OAuth(
    @SerialName("client_config") val clientConfig: OAuthClientConfig
)
