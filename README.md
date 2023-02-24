# CertificateHelper

## Overview

This is a simple helper program to handle X509 certificates in various formats. It allows to download the full
certificate chain from a server (up to and including the root certificate) and show a summary or store it as a PEM
file (optionally Base64 encoded).

## Installation

You can then build the Jar using `./gradew uber` to generate an "uber" (or "fat") Jar, or download that Jar from the
"Releases" page.  If you build the Jar yourself, then you will find it in `build/libs`.

The code is built using Java 17 and thus requires Java 17 or higher to execute it. Some examples on how to install if it is
missing:
 - Debian: `apt install openjdk-17-jre`
 - MacOS: `brew install openjdk` (which currently installs Java 19) or `brew install openjdk@17`.

If you install it, then this also often requires to set the JAVA_HOME environment variable correctly:
```shell
# for Debian
export JAVA_HOME=/var/lib/jdk/openjdk-17
# for MacOS with Java 17
export JAVA_HOME=/opt/homebrew/Cellar/openjdk@17/17.0.6
# for MacOS with Java 19
export JAVA_HOME=/opt/homebrew/Cellar/openjdk/19.0.2
```

## Usage

Typical use case is to first look at a certificate chain for a server using the following command (replace
`api.github.com` with the name of the server you are interested in):
```shell
$JAVA_HOME/bin/java -jar build/libs/CertificateHelper-1.4.0-alpha-uber.jar -i api.github.com
```
To simplify the command, consider defining a Shell function (for Bash or Zsh). Assuming you are in the top-level
directory of the cloned repository, use something like
```shell
jar=$(realpath build/libs/*-uber.jar)
function ch {
  typeset -g ch_jar
  : ${ch_jar:=$jar}
  $JAVA_HOME/bin/java -jar $ch_jar "$@"
}
```
which simplifies the command to `ch -i api.github.com`.
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
ch -f config -i config/dev.json -k github.tls.caBundleBase64
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

If you are only interested in a single certificate instead of the whole certificate chain, then you can use the 
`--certIndex` option to select that certificate. The leaf certificate always has index 0.  Thus, to only get the 
leaf certificate from a server, add `-c 0`.

Run `ch --help` to see all the options:
```text
Usage: ch [OPTIONS]

  Reads or updates certificates from server, file, or vault. Example:

  ch -f server -i api.github.com

Options:
  --generate-completion [bash|zsh|fish]
  -i, --input TEXT                                     Input file or server name; - for stdin (default: -)
  -f, --inputFormat [SERVER|CONFIG|PEM|BASE64|VAULT]   Input format (default: SERVER)
  -k, --key TEXT                                       Config key
  -p, --port INT                                       Server port (default: 443)
  -o, --output TEXT                                    Output file name; - for stdout (default: -)
  -t, --outputFormat [SUMMARY|TEXT|PEM|BASE64|CONFIG]  Output format (default: SUMMARY)
  -c, --certIndex INT                                  Certificate indices (comma-separated) (default: all certificates)
  -h, --help                                           Show this message and exit

Vault operations need a current vault token. This can be provided either via the environment variable VAULT_TOKEN, or via the file
$HOME/.vault-token. The latter is automatically created when using the command "vault login". The token (normally valid for 24
hours) can be generated after signing into the vault using the URL (requires Okta Yubikey authentication)
https://hashicorp-vault.corp.creditkarma.com:6661/ui/vault/auth?with=okta_oidc and then using the "Copy Token" menu entry from the
top-right user menu.
```

Note: The `text` output format is a non-standard format and not the usual `openssl x509 -text` format. If you need
the latter, use `CerificateHelper` to get the certificates in PEM format and then pipe them into `openssl`.

## Examples

All these assume you use the `ch` function described above.

1. Show the summary of the certificate chain of server `api.github.com`
    ```shell
    ch -i api.github.com 
    ```
2. Show leaf certificate of `api.github.com` in OpenSSL text format
    ```shell
    ch -i api.github.com -t pem -c 0 | openssl x509 -noout -text
    ```
3. Update Base64-encoded certificate in `config.json` file from current server 
    ```shell
    ch -i api.github.com -t config -k github.tls.caBundle -o config.json
    ```
