# CertificateHelper

This is a simple helper program to handle X509 certificates in various formats. It allows to download the full
certificate chain from a server (up to and including the root certificate) and show a summary or store it as a PEM
file (optionally Base64 encoded).

The code is built using Java 17 and thus requires Java 17 to execute it. Some examples:
 - Debian: `apt install openjsk-17-jre`
 - MacOS: `brew install openjdk@17` (and then following the instructions)

This then also requires setting JAVA_HOME correctly.

Typical use case is to first look at a certificate chain for a server using

```shell
$JAVA_HOME/bin/java -jar build/libs/CertificateHelper-1.0-uber.jar -i api.github.com
```
results in something like
```text
api.github.com: X509 certificate for *.github.com
	SHA256 fingerprint: FACB6EEE2853E5874A658BDF95F096BE20DC088677CBEC34D69CA0BD737C5FF9
	SHA256 public key: BB23D881C95CE49B7AF6F2AEF76BDC8BA7AD7010D8F14353CAB1D0649A55A196
	Expires: 2023-03-16T23:59:59Z
	DNS names: [*.github.com, github.com]

api.github.com: X509 certificate for DigiCert TLS Hybrid ECC SHA384 2020 CA1
	SHA256 fingerprint: F7A9A1B2FD964A3F2670BD668D561FB7C55D3AA9AB8391E7E169702DB8A3DBCF
	SHA256 public key: 7B4211CF94E2A37180D57B387D4556987D711C3887D9D31B56D0814A438876A3
	Expires: 2031-04-13T23:59:59Z
```

You can then store these in a file in PEM format using `... -t pem -o github.pem`, or as a Base64-encoded PEM using
`... -t base64 -o github.b64`.

The program can also read certificates from files (in PEM or Base-64-encoded PEM format), or extract them from JSON
configuration files:
```shell
$JAVA_HOME/bin/java -jar build/libs/CertificateHelper-1.0-uber.jar -f config -i config/dev.json -k github.tls.caBundleBase64
```
will print the summary of a Base64-encoded PEM chain stored in `config/dev.json` under the path
```text
{
  "github": {
      "tls": {
        "caBundleBase64": "DEADBEEF"
      }
  }
}
```
