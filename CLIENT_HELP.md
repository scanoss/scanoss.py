# SCANOSS Client Usage Help
This file contains useful tips/tricks for getting the most out of the SCANOSS platform using the Python client/SDK.

## Installation
### Externally Managed Environments Error
If installing on Ubuntu 2023.04, Fedora 38, Debian 11, etc. a few additional steps are required before installing `scanoss-py`. More details can be found [here](https://itsfoss.com/externally-managed-environment/).

The recommended method is to install `pipx` and use it to install `scanoss-py`:
```bash
sudo apt install pipx
pipx ensurepath
```

This will install the `pipx` package manager, which can then be used to install `scanoss-py`:
```bash
pipx install scanoss[fast_winnowing]
```
This will install the `scanoss-py` app in a separate virtual environment and create a link to the local path for execution.

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
  * `scanoss-py utils pac-proxy --pac auto --url https://api.osskb.org`
* file
  * `scanoss-py utils pac-proxy --pac file://proxy.pac --url https://api.osskb.org`
* url
  * `scanoss-py utils pac-proxy --pac https://path.to/proxy.pac --url https://api.osskb.org`

## GRPCIO Library installation for Apple Silicon (before 1.5.3)
Versions of [grpcio](https://pypi.org/project/grpcio) prior to `1.5.3` did not contain a binary wheel for Apple Silicon.

[Pietro De Nicolao](https://github.com/pietrodn) has kindly created a [GitHub repo](https://github.com/pietrodn/grpcio-mac-arm-build) to build the M1/M2 compatible wheels.
Simply browse to the [releases](https://github.com/pietrodn/grpcio-mac-arm-build/releases) area, choose the desired release version and install the wheel matching your python version:
```bash
pip3 install --upgrade https://github.com/pietrodn/grpcio-mac-arm-build/releases/download/1.51.1/grpcio-1.51.1-cp39-cp39-macosx_11_0_arm64.whl
```

This command above will install `grpcio` `1.5.1` for Python `3.9`. To install for `3.10` simply replace the `cp39` with `cp310`.

## Command Execution
There are multiple commands (and sub commands) available through `scanoss-py`.
Detailed help is available for all directly from the CLI itself:
```bash
scanoss-py --help
scanoss-py scan --help
scanoss-py comp
scanoss-py comp vulns --help
scanoss-py utils
scanoss-py inspect
```

### Fingerprint a project folder
The following command provides the capability to fingerprint (generate WFPs) for a given file/folder:
```bash
scanoss-py wfp --help
```
The following command fingerprints the `src` folder and writes the output to `src-fingers.wfp`:
```bash
scanoss-py wfp -o src-fingers.wfp src
```

This fingerprint (WFP) can then be sent to the SCANOSS engine using the scanning command:
```bash
scanoss-py scan -w src-fingers.wfp -o scan-results.json
```

### Dependency file parsing
The dependency files of a project can be fingerprinted/parsed using the `dep` command:
```bash
scanoss-py dep -o src-deps.json src
```

This parsed dependency file can then be sent to the SCANOSS for decoration using the scanning command:
```bash
scanoss-py scan --dep src-deps.json --dependencies-only -o scan-results.json
```

It is possible to combine a WFP & Dependency file into a single scan also:
```bash
scanoss-py scan -w src-fingers.wfp --dep src-deps.json -o scan-results.json
```

### Scan a project folder
The following command provides the capability to scan a given file/folder:
```bash
scanoss-py scan --help
```

The following command scans the `src` folder and writes the output to `scan-results.json`:
```bash
scanoss-py scan -o scan-results.json src
```

### Scan a project folder with dependencies
The following command scans the `src` folder for file, snippet & dependency matches, writing the output to `scan-results.json`:
```bash
scanoss-py scan -o scan-results.json -D src
```

### Scan a project folder with filtered dependency scopes
The following command scans the src folder for files, code snippets, and dependencies, specifically targeting development dependencies:
The available flags for filtering dependency scopes are **__dev__** for development dependencies or **__prod__** for production dependencies:
```bash
scanoss-py scan  -D src --dep-scope dev
```

### Scan a project folder including dependencies with declared scopes
The following command scans the src folder for files, code snippets, and dependencies, allowing you to specify which dependency scopes to include.
In this example, the scan targets the dependencies and install scopes:
```bash
scanoss-py scan  -D src --dep-scope-inc dependencies,install
```

### Scan a project folder excluding dependencies with declared scopes
The following command scans the src folder for files, code snippets, and dependencies, allowing you to specify which dependency scopes to exclude.
In this example, the scan targets dependencies but excludes those within the install scope:
```bash
scanoss-py scan  -D src --dep-scope-exc install
```

### Scan a project folder skipping files and snippets
The following command scans the `src` folder writing the output to `scan-results.json` skipping the following:
- MD5 file `37f7cd1e657aa3c30ece35995b4c59e5`
- Header files `.h`
- Files smaller than 512 byes
- Files inside folder `internal`
- Snippets matching `d5e54c33,b03faabe`
```bash
scanoss-py scan -o scan-results.json -5 37f7cd1e657aa3c30ece35995b4c59e5 -E '.h' -Z 512 -O internal -N 'd5e54c33,b03faabe' src
```

### Converting RAW results into other formats
The following command provides the capability to convert the RAW scan results from a SCANOSS scan into multiple different formats, including CycloneDX, SPDX Lite, CSV, etc.
For the full set of formats, please run:
```bash
scanoss-py cnv --help
```

The following command converts `scan-results.json` to SPDX Lite:
```bash
scanoss-py cnv --input scan-results.json --format spdxlite --output scan-results-spdxlite.json
```

### Component Commands
The `component` command has a suite of sub-commands designed to operate on OSS components. For example:
* Vulnerabilities (`vulns`)
* Search (`search`)
* Version Details (`versions`)
* Cryptography (`crypto`)

For the latest list of sub-commands, please run:
```bash
scanoss-py comp --help
```

#### Component Vulnerabilities
The following command provides the capability to search the SCANOSS KB for component vulnerabilities:
```bash
scanoss-py comp vulns -p "pkg:github/unoconv/unoconv"
```
It is possible to supply multiple PURLs by repeating the `-p pkg` option, or providing a purl input file `-i purl-input.json` ([for example](tests/data/purl-input.json)):
```bash
scanoss-py comp vulns -i purl-input.json -o vulnernable-comps.json
```

#### Component Search
The following command provides the capability to search the SCANOSS KB for an Open Source component:
```bash
scanoss-py comp search --key $SC_API_KEY -s "unoconv"
```
This command will search through different combinations to retrieve a proposed list of components (i.e. vendor/component, component, vendor, purl).

It is also possible to search by component and vendor, while restricting the package type:
```bash
scanoss-py comp search --key $SC_API_KEY -c unoconv -v unoconv -p github
```
**Note:** This sub-command requires a subscription to SCANOSS premium data.

#### Component Versions
The following command provides the capability to search the SCANOSS KB for versions of a specified component PURL:
```bash
scanoss-py comp versions --key $SC_API_KEY -p "pkg:github/unoconv/unoconv"
```
**Note:** This sub-command requires a subscription to SCANOSS premium data.

#### Cryptographic Algorithms
The following command provides the capability to search the SCANOSS KB for any cryptographic algorithms detected in a specified component PURL:
```bash
scanoss-py comp crypto --key $SC_API_KEY -p "pkg:github/unoconv/unoconv"
```
It is possible to supply multiple PURLs by repeating the `-p pkg` option, or providing a purl input file `-i purl-input.json` ([for example](tests/data/purl-input.json)):
```bash
scanoss-py comp crypto --key $SC_API_KEY -i purl-input.json -o crypto-components.json
```
**Note:** This sub-command requires a subscription to SCANOSS premium data.

#### Semgrep Issues/Findings
The following command provides the capability to search the SCANOSS KB for any semgrep issues detected in a specified component PURL:
```bash
scanoss-py comp semgrep --key $SC_API_KEY -p "pkg:github/spring-projects/spring-data-jpa"
```
It is possible to supply multiple PURLs by repeating the `-p pkg` option, or providing a purl input file `-i purl-input.json` ([for example](tests/data/purl-input.json)):
```bash
scanoss-py comp semgrep --key $SC_API_KEY -i purl-input.json -o semgrep-issues.json
```
**Note:** This sub-command requires a subscription to SCANOSS premium data.

### Results Commands
The `results` command provides the capability to operate on scan results. For example:

The following command gets the pending results from a scan:
```bash
scanoss-py results results.json --has-pending
```

You can indicate the output format and an output file:
```bash
scanoss-py results results.json --format json --output results-output.json
```

You can also filter the results by either status or match type:
```bash
scanoss-py results results.json --status pending --match-type file
```

You can provide a comma separated list of statuses or match types:
```bash
scanoss-py results results.json --status pending,identified --match-type file,snippet
```


### Inspect Commands
The `inspect` command has a suite of sub-commands designed to inspect the results.json.
Details, such as license compliance or component declarations, can be examined.

For example:
* Copyleft (`copylefet`)
* Undeclared Components (`undeclared`)

For the latest list of sub-commands, please run:
```bash
scanoss-py insp --help
```
#### Inspect Copyleft
The following command can be used to inspect for copyleft licenses.
If no output or status flag is defined, details are exposed via stdout and the summary is provided via stderr.
Default format 'json'
```bash
scanoss-py insp copyleft -i scan-results.json
```

#### Inspect for copyleft licenses and save results
The following command can be used to inspect for copyleft licenses and save the results.
Default output format 'json'.
```bash
scanoss-py insp copyleft -i scan-results.json --status status.md --output copyleft.json
```

#### Inspect for copyleft licenses and save results in Markdown format
The following command can be used to inspect for copyleft licenses and save the results in Markdown format.
```bash
scanoss-py insp copyleft -i scan-results.json --status status.md --output copyleft.md --format md
```

#### Inspect for undeclared components
The following command can be used to inspect for undeclared components.
If no output or status flag is defined, details are exposed via stdout and the summary is provided via stderr.
Default output format 'json'.
```bash
scanoss-py insp undeclared -i scan-results.json 
```

#### Inspect for undeclared components and save results
The following command can be used to inspect for undeclared components and save the results.
Default output format 'json'.
```bash
scanoss-py insp undeclared -i scan-results.json --status undeclared-status.md --output undeclared.json
```

#### Inspect for undeclared components and save results in Markdown format
The following command can be used to inspect for undeclared components and save the results in Markdown format.
```bash
scanoss-py insp undeclared -i scan-results.json --status undeclared-status.md --output undeclared.json --format md
```

#### Inspect for undeclared components and save results in Markdown format and styled as sbom.json
The following command can be used to inspect for undeclared components and save the results in Markdown format.
Default status style 'scanoss-json'
```bash
scanoss-py insp undeclared -i scan-results.json --status undeclared-status.md --output undeclared.json --format md --style sbom
```