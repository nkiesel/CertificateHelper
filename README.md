# CertificateHelper

## Overview

This is a simple helper program to handle X509 certificates in various formats. It allows to download the full
certificate chain from a server (up to and including the root certificate) and show a summary or store it as a PEM
file (optionally Base64 encoded).

## Installation

You can then build the Jar using `./gradew uber` to generate an "uber" (or "fat") Jar, or download that Jar from the
"Releases" page.

The code is built using Java 17 and thus requires Java 17 to execute it. Some examples on how to install if it is
missing:
 - Debian: `apt install openjsk-17-jre`
 - MacOS: `brew install openjdk@17` (and then following the instructions)

If you install it, then this also often requires to set the JAVA_HOME environment variable correctly.

## Usage

Typical use case is to first look at a certificate chain for a server using the following command (replace
`api.github.com` with the host name you are interested in):
```shell
$JAVA_HOME/bin/java -jar CertificateHelper-1.0-uber.jar -i api.github.com
```
This results in something like
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

You can then store these certificates in a file in PEM format using `... -t pem -o github.pem`, or as a Base64-encoded
PEM using `... -t base64 -o github.b64`.

The program can also read certificates from files (in PEM or Base-64-encoded PEM format), or extract them from JSON
configuration files:
```shell
$JAVA_HOME/bin/java -jar CertificateHelper-1.0-uber.jar -f config -i config/dev.json -k github.tls.caBundleBase64
```
will print the summary of a Base64-encoded PEM chain stored in `config/dev.json` under the path
```json
{
  "github": {
      "tls": {
        "caBundleBase64": "LS0tLS1CRUd...RS0tLS0tCg=="
      }
  }
}
```
Note: for historical reasons, a key w/o any `.` will have `.tls.caBundleBase64` appended, and thus the above
command could be shortened to `... -f config -i config/dev.json -k github`.

Run `$JAVA_HOME/bin/java -jar CertificateHelper-1.0-uber.jar -h` to see all the options:
```text
Options:
    --inputFormat, -f [SERVER] -> Input format { Value should be one of [server, config, pem, base64] }
    --input, -i -> Input (always required) { String }
    --key, -k -> Config key { String }
    --port, -p [443] -> server port { Int }
    --outputFormat, -t [SUMMARY] -> Output format { Value should be one of [pem, summary, base64, text] }
    --output, -o [-] -> Output (- for stdout) { String }
    --help, -h -> Usage info
```

Note: The `text` output format is a non-standard format and not the usual `openssl x509 -text` format. If you need
the latter, use `CerificateHelper` to get the certificates in PEM format and then pipe them into `openssl`.
