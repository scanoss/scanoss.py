# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
- Upcoming changes...

## [1.11.1] - 2024-03-18
### Added
- Integrate CURL and jq
  - Includes CURL and jq within the Docker image to facilitate seamless interactions with third-party integrations.

## [1.11.0] - 2024-03-13
### Added
- Added scan/wfp file filtering options
  - Exclude files matching MD5 `--skip-md5` (repeat as needed)
  - Strip code fragments using HPSM `--strip-hpsm` (repeat as needed)
  - Strip code fragments using snippet IDs `--strip-snippet` (repeat as needed)

## [1.10.0] - 2024-02-09
### Added
- Added scan/wfp file filtering options
  - Exclude file extensions `--skip-extension` (repeat as needed)
  - Exclude folder `--skip-folder` (repeat as needed)
  - Exclude files smaller than specified `--skip-size`
- Added `scan_files_with_options` SDK capability
  - Enables a programmer to supply a specific list of files to scan

## [1.9.0] - 2023-12-29
### Added
- Added dependency file decoration option to scanning (`scan`) using `--dep`
  - More details can be found in [CLIENT_HELP.md](CLIENT_HELP.md)

## [1.8.0] - 2023-11-13
### Added
- Added Component Decoration sub-command:
  - Semgrep (`scanoss-py comp semgrep`)

## [1.7.0] - 2023-09-15
### Added
- Added Component Decoration sub-commands:
  - Search (`scanoss-py comp search`)
  - Versions (`scanoss-py comp versions`)
  - Vulnerabilities (`scanoss-py comp vulns`)

## [1.6.3] - 2023-08-22
### Changed
- Changed default scan POST size to 32k
- Changed default scanning threads to 5 (and timeout to 180 seconds)
- Improved HPSM generation performance

## [1.6.2] - 2023-08-11
### Added
- Added `.woff2` to the list of file type to skip while scanning

## [1.6.1] - 2023-07-06
### Fixed
- Fixed issue with CSV dependency generation
- Increased `scanoss-winnowing` minimum requirement to match HPSM support

## [1.6.0] - 2023-06-16
### Added
- Added support for High Precision Snippet Matching (`--hpsm` or `-H`) while scanning
  - `scanoss-py scan --hpsm ...` 

## [1.5.2] - 2023-06-13
### Added
- Added retry limit option (`--retry`) while scanning 
  - `--retry 0` will fail immediately

## [1.5.1] - 2023-04-21
### Added
- Added support scanning/fingeprinting file contents from STDIN
  - `cat test.py | scanoss-py scan --stdin test.py -o results.json`
  - `cat test.py | scanoss-py wfp --stdin test.py -o fingers.wfp`

## [1.5.0] - 2023-03-21
### Added
- Added support for component cryptographic reporting
  - `scanoss-py component crypto ...`

## [1.4.2] - 2023-03-09
### Fixed
- Fixed issue with custom certificate when scanning (--ca-cert)
### Added
- Added support to download full certificate chain with:
  - `cert_download.sh`
  - `scanoss-py utils cdl`

## [1.4.0] - 2023-03-01
### Added
- Added support for fast winnowing (15x improvement) thanks to a contribution from [tardyp](https://github.com/tardyp)
  - This is enabled by a supporting package; [scanoss_winnowing](https://github.com/scanoss/scanoss-winnowing.py).
  - It can be installed using: `pip3 install scanoss_winnowing`
  - Or using: `pip3 install --upgrade scanoss[fast_winnowing]`

## [1.3.7] - 2023-02-07
### Added
- Upgrade to the latest protobuf and grpcio packages
- Added GH Actions for building

## [1.3.6] - 2023-02-02
### Added
- Added support for Proxy Auto-Config (--pac) and GRPC proxy (--grpc-proxy)

## [1.3.5] - 2023-01-31
### Added
- Added extra fields to CSV output (detected_url, detected_path)

## [1.3.4] - 2023-01-16
### Added
- Added User-Agent client/version to requests

## [1.3.3] - 2023-01-06
### Added
- Added support for handling 503 service unavailable responses
- Added latest SPDX license definitions (2.2.7)

## [1.3.2] - 2022-12-28
### Added
- Added `x-request-id` to all scanning requests
- Added bad_request error log file to aid debug
### Fixed
- Fixed issue when fingerprinting large files with a small POST (`--post-size`)

## [1.3.1] - 2022-12-07
### Added
- Added `utils cert-download` sub-command to help with the use of custom certificates
  - Included a local certificate download script leveraging openssl too: [cert_download.sh](cert_download.sh)
- Added [documentation](CLIENT_HELP.md) to help with certificate and proxy configuration

## [1.3.0] - 2022-12-02
### Added
- Added support for proxy (--proxy) and certificates (--ca-certs) while scanning
  - Certificates can also be supplied using environment variables: REQUESTS_CA_BUNDLE & GRPC_DEFAULT_SSL_ROOTS_FILE_PATH
  - Proxies can be supplied using: grpc_proxy, https_proxy, http_proxy, HTTPS_PROXY, HTTP_PROXY
- Added snippet match fields to CSV output
- Added `convert` command to convert raw JSON reports into CSV, CycloneDX and SPDXLite
- Added `utils certloc` sub-command to print the location of Python's CA Cert file
  - This is useful to know where to append custom certificates to if needed

## [1.2.3] - 2022-11-22
### Added
- Added Max Threaded scanning override env var (SCANOSS_MAX_ALLOWED_THREADS)
  If the backend system can handle more than the current maximum (30), then set this env to that number
  `export SCANOSS_MAX_ALLOWED_THREADS=40`

## [1.2.2] - 2022-11-18
### Added
- Added SSL cert error ignore option (--ignore-cert-errors) for REST calls
  Custom certificates can be supplied using environment variables
- Added multi-platform Docker images (AMD64 & ARM64)

## [1.2.1] - 2022-11-11
### Added
- Added sub-command (file_count)to produce a file summary (extensions & size) into a CSV

## [1.2.0] - 2022-11-08
### Added
- Added vulnerability reporting to CycloneDX output
- Added obfuscation to fingerprinting (--obfuscate)
- Added obfuscation to scanning (--obfuscate)

## [1.1.1] - 2022-10-19
### Fixed
- Fixed issue with dependency parsing of yarn.lock files

## [1.1.0] - 2022-10-12
### Fixed
- Added LicenseRef info to SPDX Lite output
- Updated CycloneDX output format to support version 1.4
### Added
- Added request id to gRPC requests

## [1.0.6] - 2022-09-19
### Added
- Added support for scancode 2.0 output format

## [1.0.4] - 2022-09-07
### Fixed
- Fixed spelling mistake in SPDX output
- Adjusted protobuf module requirements

## [1.0.0] - 2022-07-22
### Added
- Added support for CSV output (--format csv)
- Added documentDescribes to SPDXLite output

## [0.9.0] - 2022-06-09
### Added
- Added support for dependency scanning (--dependencies)
  - This depends on scancode to search for dependency files
- Added dependency data to output reports

## [0.7.4] - 2021-12-15
### Changed
- Updated SPDX Lite report output data (--format spdxlite)

## [0.7.3] - 2021-12-11
### Added
- Added support for SPDX Lite report output (--format spdxlite)

## [0.7.2] - 2021-12-10
### Added
- Added option to process all file extensions while scanning (--all-extensions)
- Added option to process all folders while scanning (--all-folders)
- Added option to process all hidden files/folders while scanning (--all-hidden)

## [0.7.1] - 2021-11-12
### Added
- Added option to skip WFP file generation while scanning (--no-wfp-output)

## [0.7.0] - 2021-11-08
### Added
- Added option to change default REST timeout (--timeout)
- Added threaded scanning to WFP file processing
### Changed
- Changed from GPL license to MIT
- Changed minimum Python version to 3.7

## [0.6.11] - 2021-10-18
### Added
- Added option to skip snippet generation in the client (--skip-snippets)
- Added option to tune the scan packet post size (--post-size)
- Added Docker/Container support for running the client
- Fixed threading issue while scanning

## [0.6.6] - 2021-08-20
### Fixed
- Fixed broken call for scanning WFP file only

## [0.6.5] - 2021-07-15
### Added
- Added support to start scanning while fingerprinting to further increase scan performance
### Fixed
- Ignoring broken symlink files

## [0.6.0] - 2021-07-14
### Added
- Added threading to speed up fingerprint scanning

## [0.5.6] - 2021-07-12
### Added
- Added changelog

## [0.5.5] - 2021-07-09
### Added
- Added input SBOM JSON validation
- Added REST POST retry logic

## [0.5.4] - 2021-07-08
### Added
- Added --ignore option to scan command

## [0.5.2] - 2021-06-29
### Fixed
- Fixed filtering bug

[0.5.4]: https://github.com/scanoss/scanoss.py/compare/v0.5.2...v0.5.4
[0.5.5]: https://github.com/scanoss/scanoss.py/compare/v0.5.4...v0.5.5
[0.5.6]: https://github.com/scanoss/scanoss.py/compare/v0.5.5...v0.5.6
[0.6.0]: https://github.com/scanoss/scanoss.py/compare/v0.5.6...v0.6.0
[0.6.5]: https://github.com/scanoss/scanoss.py/compare/v0.6.0...v0.6.5
[0.6.6]: https://github.com/scanoss/scanoss.py/compare/v0.6.5...v0.6.6
[0.6.11]: https://github.com/scanoss/scanoss.py/compare/v0.6.6...v0.6.11
[0.7.0]: https://github.com/scanoss/scanoss.py/compare/v0.6.11...v0.7.0
[0.7.1]: https://github.com/scanoss/scanoss.py/compare/v0.7.0...v0.7.1
[0.7.2]: https://github.com/scanoss/scanoss.py/compare/v0.7.1...v0.7.2
[0.7.3]: https://github.com/scanoss/scanoss.py/compare/v0.7.2...v0.7.3
[0.7.4]: https://github.com/scanoss/scanoss.py/compare/v0.7.3...v0.7.4
[0.9.0]: https://github.com/scanoss/scanoss.py/compare/v0.7.4...v0.9.0
[1.0.0]: https://github.com/scanoss/scanoss.py/compare/v0.9.0...v1.0.0
[1.0.4]: https://github.com/scanoss/scanoss.py/compare/v1.0.0...v1.0.4
[1.0.6]: https://github.com/scanoss/scanoss.py/compare/v1.0.4...v1.0.6
[1.1.0]: https://github.com/scanoss/scanoss.py/compare/v1.0.6...v1.1.0
[1.1.1]: https://github.com/scanoss/scanoss.py/compare/v1.1.0...v1.1.1
[1.2.0]: https://github.com/scanoss/scanoss.py/compare/v1.1.1...v1.2.0
[1.2.1]: https://github.com/scanoss/scanoss.py/compare/v1.2.0...v1.2.1
[1.2.2]: https://github.com/scanoss/scanoss.py/compare/v1.2.1...v1.2.2
[1.2.3]: https://github.com/scanoss/scanoss.py/compare/v1.2.2...v1.2.3
[1.3.0]: https://github.com/scanoss/scanoss.py/compare/v1.2.3...v1.3.0
[1.3.1]: https://github.com/scanoss/scanoss.py/compare/v1.3.0...v1.3.1
[1.3.2]: https://github.com/scanoss/scanoss.py/compare/v1.3.1...v1.3.2
[1.3.3]: https://github.com/scanoss/scanoss.py/compare/v1.3.2...v1.3.3
[1.3.4]: https://github.com/scanoss/scanoss.py/compare/v1.3.3...v1.3.4
[1.3.5]: https://github.com/scanoss/scanoss.py/compare/v1.3.4...v1.3.5
[1.3.6]: https://github.com/scanoss/scanoss.py/compare/v1.3.5...v1.3.6
[1.3.7]: https://github.com/scanoss/scanoss.py/compare/v1.3.6...v1.3.7
[1.4.0]: https://github.com/scanoss/scanoss.py/compare/v1.3.7...v1.4.0
[1.4.2]: https://github.com/scanoss/scanoss.py/compare/v1.4.0...v1.4.2
[1.5.0]: https://github.com/scanoss/scanoss.py/compare/v1.4.2...v1.5.0
[1.5.1]: https://github.com/scanoss/scanoss.py/compare/v1.5.0...v1.5.1
[1.5.2]: https://github.com/scanoss/scanoss.py/compare/v1.5.1...v1.5.2
[1.6.0]: https://github.com/scanoss/scanoss.py/compare/v1.5.2...v1.6.0
[1.6.1]: https://github.com/scanoss/scanoss.py/compare/v1.6.0...v1.6.1
[1.6.2]: https://github.com/scanoss/scanoss.py/compare/v1.6.1...v1.6.2
[1.6.3]: https://github.com/scanoss/scanoss.py/compare/v1.6.2...v1.6.3
[1.7.0]: https://github.com/scanoss/scanoss.py/compare/v1.6.3...v1.7.0
[1.8.0]: https://github.com/scanoss/scanoss.py/compare/v1.7.0...v1.8.0
[1.9.0]: https://github.com/scanoss/scanoss.py/compare/v1.8.0...v1.9.0
[1.10.0]: https://github.com/scanoss/scanoss.py/compare/v1.9.0...v1.10.0
[1.11.0]: https://github.com/scanoss/scanoss.py/compare/v1.10.0...v1.11.0
[1.11.1]: https://github.com/scanoss/scanoss.py/compare/v1.11.0...v1.11.1