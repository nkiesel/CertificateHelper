# CertificateHelper

## Overview

This is a simple helper program to handle X509 certificates in various formats. It allows to download the full
certificate chain from a server (up to and including the root certificate), and show a summary or store it as a PEM
file (optionally Base64 encoded).

## Installation

The code is built using Java 17 and thus requires Java 17 or higher to execute it. Some examples on how to install 
if it is missing:
 - Debian: `apt install openjdk-17-jdk`
 - MacOS: `brew install openjdk@17`

If you install it, then this also often requires to set the JAVA_HOME environment variable correctly:
```shell
# for Debian
export JAVA_HOME=/var/lib/jdk/openjdk-17
# for MacOS
export JAVA_HOME=/Library/Java/JavaVirtualMachines/openjdk-17.jdk/Contents/Home
```

Once you have Java 17 installed, you can build the Jar using `./gradlew clean uber` to generate an "uber" (or "fat") 
jar (which includes all the 3rd party dependencies). This will produce a single jar file in `build/libs`.  You can
then test the build running `java -jar build/libs/*.jar --help`. If this complains about Java not found or being an 
incompatible version, try `$JAVA_HOME/bin/java -jar build/libs/*.jar --help`.

## Usage

Typical use case is to first look at a certificate chain for a server using the following command (replace
`api.github.com` with the name of the server you are interested in):
```shell
$JAVA_HOME/bin/java -jar build/libs/CertificateHelper-*-uber.jar -f server -i api.github.com
```
To simplify the command, consider defining a Shell function (for Bash or Zsh). Assuming you are in the top-level
directory of the cloned repository, use
```shell
jar=$(realpath build/libs/*-uber.jar)
function ch {
  typeset -g ch_jar
  : ${ch_jar:=$jar}
  $JAVA_HOME/bin/java -jar $ch_jar "$@"
}
```
which simplifies the command to `ch -f server -i api.github.com`.
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
ch -f json -i config/dev.json -k github.tls.caBundleBase64
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

For historical reasons, a JSON config file in a proprietary format can be used with `--inputFormat=CONFIG`, 
where key will be extended by `.tls.hostName` for hostname lookups and by `.tls.caBundleBase64` otherwise. Thus, the 
above command for such config files could be further shortened to
```shell
ch -i config/dev.json -k github
```

If you are only interested in a single certificate instead of the whole certificate chain, then you can use the 
`--certIndex` option to select that certificate. The leaf certificate always has index 0.  Thus, to only get the 
leaf certificate from a server, add `-c 0`, and use `-c0,3` to get the 1st and 4th certificate in a chain.

Run `ch --help` to see all the options:
```text
Usage: ch [<options>]

  Reads or updates certificates from server, config, file, or vault. Example:
  ╭──────────────────────────────╮
  │ch -f server -i api.github.com│
  ╰──────────────────────────────╯

Options:
  --generate-completion=(bash|zsh|fish)
  -v, --version                                            Show the version and exit
  -i, --input=<text>                                       Input file or server name; - for stdin
  -f, --inputFormat=(SERVER|JSON|PEM|BASE64|VAULT|CONFIG)  Input format
  -n, --hostName                                           CA bundle using server name from config
  -j, --jwe                                                JWE info from config
  -b, --bundle                                             CA bundle info from config
  -k, --key=<text>                                         Config key
  --cleanup                                                Clean up certificates (remove duplicates, drop expired)
  -p, --port=<int>                                         Server port
  -o, --output=<text>                                      Output file name; - for stdout
  -t, --outputFormat=(SUMMARY|TEXT|PEM|BASE64|CONFIG)      Output format
  -c, --certIndex=<int>                                    Certificate indices (comma-separated)
  --timeout=<value>                                        Server connection timeout; 0s for no timeout
  -h, --help                                               Show this message and exit

Vault operations need a current vault token. This can be provided either via the environment variable VAULT_TOKEN, or via the file $HOME/.vault-token. The latter is automatically created when using the command "vault login". The token (normally valid for 24 hours) can be generated
after signing into the vault and then using the "Copy Token" menu entry from the top-right user menu.
```

Note: The `text` output format is a non-standard format and not the usual `openssl x509 -text` format. If you need
the latter, use `ch` to get the certificates in PEM format and then pipe them into `openssl`: 
```shell
 `ch -f SERVER -i api.github.com -t PEM -c0 | openssl x509 -noout -text`
```

## Examples

All these assume you use the `ch` function described above.

1. Show the summary of the certificate chain of server `api.github.com`
    ```shell
    ch -f server -i api.github.com 
    ```
2. Show the summary of the certificate chain of configured host for partner `github` in `default.json`
    ```shell
    ch --input default.json -f json --key github.tls.caBundleBase64
    ch --input default.json -k github
    ```
3. Show the summary of the certificate chain of configured host for partner `github` in `default.json`
    ```shell
    ch --input default.json --key github --hostName 
    ```
4. Show leaf certificate of `api.github.com` in text format
    ```shell
    ch -f server -i api.github.com -t pem -c 0 | openssl x509 -noout -text
    ch -f server -i api.github.com -t text -c 0
    ```
5. Update Base64-encoded certificate chain in `config.json` file from current server 
    ```shell
    ch -f server -i api.github.com -t config -k github -o config.json
    ```
