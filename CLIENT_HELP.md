# SCANOSS Client Usage Help
This file contains useful tips/tricks for getting the most out of the SCANOSS platform using the Python client/SDK.

## Certificate Management
The SCANOSS SaaS platform runs over HTTPS with publicly signed SSL certificates.
However, on-premise installations, or those with a proxy in the middle might be leveraging self-signed versions.

This can cause issues for the SCANOSS clients.

### Certificate Download
In order to connect to a self-signed endpoint, it's necessary to download that cert and add it to the trust store for the client.
The following is an OpenSSL-based command script which can produce this file:
```shell
cert_download.sh -n <hostname>
```
Simply pass in the hostname `-n scanoss.com` and optionally the port `-p 8443` (defaults to `443`) and it will produce a PEM file called `scanoss.com.pem`.

The `scanoss-py` CLI also supports certificate download using this command:
```shell
scanoss-py utils cdl -n scanoss.com -o scanoss-com.pem
```

It is also possible to download the certificate using a web browser, for example FireFox. Simply browse to the site, view the certificate and choose to download.

### Use Custom Certificate with CLI
There are a number of ways to leverage this custom certificate from the `scanoss-py` CLI.
- Environment Variables
- Command Line Options
- Appending to the default certificates

#### Custom Certificate with Env Vars
The `scanoss-py` CLI uses two communication methods; REST & gRPC and as such requires two env vars to be set if following this method.
- REST - Use `REQUESTS_CA_BUNDLE`
  - `export REQUESTS_CA_BUNDLE=/path/to/cert.pem`
- gRPC - Use `GRPC_DEFAULT_SSL_ROOTS_FILE_PATH`
  - `export GRPC_DEFAULT_SSL_ROOTS_FILE_PATH=/path/to/cert.pem`

#### Custom Certificate with CLI Options
The `scanoss-py` CLI has a `--ca-cert` option to allow the specification of a custom certificate file to be used when communicating over REST/gRPC.
Simply set it using:
```shell
scanoss-py scan --ca-cert scanoss-com.pem -o results.json .
```
Alternative API Urls can also be configured (if necessary) using `--apiurl` & `api2url`.

#### Custom Certificate appended to Defaults
It is also possible to append this custom certificate to the default certificate list used by `scanoss-py`.
This file location can be determined by using:
```shell
scanoss-py utils cl
```
The resulting certificate file name can then be opened and the custom certificate appended to the end.
For example:
```shell
cat scanoss-com.pem >> /usr/local/lib/python3.10/site-packages/certifi/cacert.pem
```

## Proxy Configuration
The SCANOSS clients can be configured to work with proxies. There are a number of ways to achieve this:

- Environment Variables
- Command Line Options

### Proxy Env Vars
There are a number of environment variables that can be specified to force the `scanoss-py` command to route calls via proxy.

- REST - `https_proxy`, `http_proxy`, `HTTPS_PROXY`, `HTTP_PROXY`
- gRPC - `grpc_proxy`, `https_proxy`, `http_proxy`

Set the variable as follows: `export https_proxy="http://<ip-addr>:<port>"`

The REST client support both lowercase & uppercase proxy names, however the gRPC client only supports lowercase variants. The gRPC client provides one extra variable, `grpc_proxy` to enable a separate proxy to be leveraged for it alone.

### Proxy CLI Options
The proxy for REST based calls can also be configured directly on the `scanoss-py` commandline using `--proxy`. For example:
```shell
scanoss-py scan --proxy "http://<ipaddr>:<port>" -o results.json .
```
If a separate proxy is required for GRPC calls, please use the `--grpc-proxy` option:
```shell
scanoss-py scan --proxy "http://<ipaddr>:<port>" --grpc-proxy "http://<ipaddr>:<port>" -D -o results.json .
```

### Proxy Auto-Config CLI Options
The `scanoss-py` CLI also supports Proxy Auto-Config (PAC) when scanning using the `--pac` command option.

It supports three options:
* auto - check the system for a PAC configuration
  * `scanoss-py scan --pac auto -o results.json .`
* file - load a local PAC file
  * `scanoss-py scan --pac file://proxy.pac -o results.json .`
* url - download a specific PAC file
  * `scanoss-py scan --pac https://path.to/proxy.pac -o results.json .`

### PAC File Evaluation
The `scanoss-py` CLI provides a utility command to help identify if traffic to the SCANOSS services is required over a proxy or not.

Simply run the following commands find out:
* auto
  * `scanoss-py utils pac-proxy --pac auto --url https://osskb.org`
* file
  * `scanoss-py utils pac-proxy --pac file://proxy.pac --url https://osskb.org`
* url
  * `scanoss-py utils pac-proxy --pac https://path.to/proxy.pac --url https://osskb.org`
