# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
- Upcoming changes...

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
