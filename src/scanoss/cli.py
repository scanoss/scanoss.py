"""
SPDX-License-Identifier: MIT

  Copyright (c) 2021, SCANOSS

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.
"""

import argparse
import os
import sys
import traceback
from dataclasses import asdict
from pathlib import Path
from typing import List

import pypac

from scanoss.cryptography import Cryptography, create_cryptography_config_from_args
from scanoss.delta import Delta
from scanoss.export.dependency_track import DependencyTrackExporter
from scanoss.scanners.container_scanner import (
    DEFAULT_SYFT_COMMAND,
    DEFAULT_SYFT_TIMEOUT,
    ContainerScanner,
    create_container_scanner_config_from_args,
)
from scanoss.scanners.folder_hasher import (
    FolderHasher,
    create_folder_hasher_config_from_args,
)
from scanoss.scanossgrpc import (
    ScanossGrpc,
    ScanossGrpcError,
    create_grpc_config_from_args,
)

from . import __version__
from .components import Components
from .constants import (
    DEFAULT_API_TIMEOUT,
    DEFAULT_COPYLEFT_LICENSE_SOURCES,
    DEFAULT_HFH_DEPTH,
    DEFAULT_HFH_MIN_ACCEPTED_SCORE,
    DEFAULT_HFH_RANK_THRESHOLD,
    DEFAULT_HFH_RECURSIVE_THRESHOLD,
    DEFAULT_POST_SIZE,
    DEFAULT_RETRY,
    DEFAULT_TIMEOUT,
    MIN_TIMEOUT,
    PYTHON_MAJOR_VERSION,
    VALID_LICENSE_SOURCES,
)
from .csvoutput import CsvOutput
from .cyclonedx import CycloneDx
from .filecount import FileCount
from .gitlabqualityreport import GitLabQualityReport
from .inspection.policy_check.dependency_track.project_violation import (
    DependencyTrackProjectViolationPolicyCheck,
)
from .inspection.policy_check.scanoss.copyleft import Copyleft
from .inspection.policy_check.scanoss.undeclared_component import UndeclaredComponent
from .inspection.summary.component_summary import ComponentSummary
from .inspection.summary.license_summary import LicenseSummary
from .inspection.summary.match_summary import MatchSummary
from .results import Results
from .scancodedeps import ScancodeDeps
from .scanner import FAST_WINNOWING, Scanner
from .scanners.scanner_config import create_scanner_config_from_args
from .scanners.scanner_hfh import ScannerHFH
from .scanoss_settings import ScanossSettings, ScanossSettingsError
from .scantype import ScanType
from .spdxlite import SpdxLite
from .threadeddependencies import SCOPE
from .utils.file import validate_json_file

HEADER_PARTS_COUNT = 2


def print_stderr(*args, **kwargs):
    """
    Print the given message to STDERR
    """
    print(*args, file=sys.stderr, **kwargs)


def setup_args() -> None:  # noqa: PLR0912, PLR0915
    """
    Setup all the command line arguments for processing
    """
    parser = argparse.ArgumentParser(
        description=f'SCANOSS Python CLI. Ver: {__version__}, License: MIT, Fast Winnowing: {FAST_WINNOWING}'
    )
    parser.add_argument('--version', '-v', action='store_true', help='Display version details')

    subparsers = parser.add_subparsers(
        title='Sub Commands', dest='subparser', description='valid subcommands', help='sub-command help'
    )
    # Sub-command: version
    p_ver = subparsers.add_parser(
        'version', aliases=['ver'], description=f'Version of SCANOSS CLI: {__version__}', help='SCANOSS version'
    )
    p_ver.set_defaults(func=ver)

    # Sub-command: scan
    p_scan = subparsers.add_parser(
        'scan',
        aliases=['sc'],
        description=f'Analyse/scan the given source base: {__version__}',
        help='Scan source code',
    )
    p_scan.set_defaults(func=scan)
    p_scan.add_argument('scan_dir', metavar='FILE/DIR', type=str, nargs='?', help='A file or folder to scan')
    p_scan.add_argument('--wfp', '-w', type=str, help='Scan a WFP File instead of a folder (optional)')
    p_scan.add_argument('--dep', '-p', type=str, help='Use a dependency file instead of a folder (optional)')
    p_scan.add_argument(
        '--stdin', '-s', metavar='STDIN-FILENAME', type=str, help='Scan the file contents supplied via STDIN (optional)'
    )
    p_scan.add_argument('--files', '-e', type=str, nargs='*', help='List of files to scan.')
    p_scan.add_argument('--identify', '-i', type=str, help='Scan and identify components in SBOM file')
    p_scan.add_argument('--ignore', '-n', type=str, help='Ignore components specified in the SBOM file')
    p_scan.add_argument(
        '--threads', '-T', type=int, default=5, help='Number of threads to use while scanning (optional - default 5)'
    )
    p_scan.add_argument(
        '--flags',
        '-F',
        type=int,
        help='Scanning engine flags (1: disable snippet matching, 2 enable snippet ids, '
        '4: disable dependencies, 8: disable licenses, 16: disable copyrights,'
        '32: disable vulnerabilities, 64: disable quality, 128: disable cryptography,'
        '256: disable best match only, 512: hide identified files, '
        '1024: enable download_url, 2048: enable GitHub full path, '
        '4096: disable extended server stats)',
    )
    p_scan.add_argument(
        '--post-size',
        '-P',
        type=int,
        default=DEFAULT_POST_SIZE,
        help='Number of kilobytes to limit the post to while scanning (optional - default 32)',
    )
    p_scan.add_argument(
        '--timeout',
        '-M',
        type=int,
        default=DEFAULT_TIMEOUT,
        help='Timeout (in seconds) for API communication (optional - default 180)',
    )
    p_scan.add_argument(
        '--retry',
        '-R',
        type=int,
        default=DEFAULT_RETRY,
        help='Retry limit for API communication (optional - default 5)',
    )
    p_scan.add_argument('--dependencies', '-D', action='store_true', help='Add Dependency scanning')
    p_scan.add_argument('--dependencies-only', action='store_true', help='Run Dependency scanning only')
    p_scan.add_argument(
        '--sc-command', type=str, help='Scancode command and path if required (optional - default scancode).'
    )
    p_scan.add_argument(
        '--sc-timeout',
        type=int,
        default=600,
        help='Timeout (in seconds) for scancode to complete (optional - default 600)',
    )
    p_scan.add_argument(
        '--dep-scope', '-ds', type=SCOPE, help='Filter dependencies by scope - default all (options: dev/prod)'
    )
    p_scan.add_argument('--dep-scope-inc', '-dsi', type=str, help='Include dependencies with declared scopes')
    p_scan.add_argument('--dep-scope-exc', '-dse', type=str, help='Exclude dependencies with declared scopes')
    p_scan.add_argument(
        '--no-wfp-output', action='store_true',
        help='DEPRECATED: Scans no longer generate scanner_output.wfp. Use "fingerprint -o" to create WFP files.'
    )
    p_scan.add_argument(
        '--wfp-output', type=str, metavar='FILE',
        help='Save fingerprints to specified file during scan'
    )

    # Sub-command: fingerprint
    p_wfp = subparsers.add_parser(
        'fingerprint',
        aliases=['fp', 'wfp'],
        description=f'Fingerprint the given source base: {__version__}',
        help='Fingerprint source code',
    )
    p_wfp.set_defaults(func=wfp)
    p_wfp.add_argument('scan_dir', metavar='FILE/DIR', type=str, nargs='?', help='A file or folder to scan')
    p_wfp.add_argument(
        '--stdin',
        '-s',
        metavar='STDIN-FILENAME',
        type=str,
        help='Fingerprint the file contents supplied via STDIN (optional)',
    )

    # Sub-command: dependency
    p_dep = subparsers.add_parser(
        'dependencies',
        aliases=['dp', 'dep'],
        description=f'Produce dependency file summary: {__version__}',
        help='Scan source code for dependencies, but do not decorate them',
    )
    p_dep.add_argument('scan_loc', metavar='FILE/DIR', type=str, nargs='?', help='A file or folder to scan')
    p_dep.add_argument(
        '--container',
        type=str,
        help='Container image to scan. Supports yourrepo/yourimage:tag, Docker tar, '
        'OCI tar, OCI directory, SIF Container, or generic filesystem directory.',
    )
    p_dep.add_argument(
        '--sc-command', type=str, help='Scancode command and path if required (optional - default scancode).'
    )
    p_dep.add_argument(
        '--sc-timeout',
        type=int,
        default=600,
        help='Timeout (in seconds) for scancode to complete (optional - default 600)',
    )
    p_dep.set_defaults(func=dependency)

    # Container scan sub-command
    p_cs = subparsers.add_parser(
        'container-scan',
        aliases=['cs'],
        description=f'Analyse/scan the given container image: {__version__}',
        help='Scan container image',
    )
    p_cs.add_argument(
        'scan_loc',
        metavar='IMAGE',
        type=str,
        nargs='?',
        help=(
            'Container image to scan. Supports yourrepo/yourimage:tag, Docker tar, '
            'OCI tar, OCI directory, SIF Container, or generic filesystem directory.'
        ),
    )
    p_cs.add_argument(
        '--retry',
        '-R',
        type=int,
        default=DEFAULT_RETRY,
        help='Retry limit for API communication (optional - default 5)',
    )
    p_cs.add_argument(
        '--timeout',
        '-M',
        type=int,
        default=DEFAULT_TIMEOUT,
        help='Timeout (in seconds) for API communication (optional - default 180)',
    )
    p_cs.set_defaults(func=container_scan)

    # Sub-command: file_count
    p_fc = subparsers.add_parser(
        'file_count',
        aliases=['fc'],
        description=f'Produce a file type count summary: {__version__}',
        help='Search the source tree and produce a file type summary',
    )
    p_fc.set_defaults(func=file_count)
    p_fc.add_argument('scan_dir', metavar='DIR', type=str, nargs='?', help='A folder to search')
    p_fc.add_argument('--all-hidden', action='store_true', help='Scan all hidden files/folders')

    # Sub-command: convert
    p_cnv = subparsers.add_parser(
        'convert',
        aliases=['cv', 'cnv', 'cvrt'],
        description=f'Convert results files between formats: {__version__}',
        help='Convert file format',
    )
    p_cnv.set_defaults(func=convert)
    p_cnv.add_argument('--input', '-i', type=str, required=True, help='Input file name')
    p_cnv.add_argument(
        '--format',
        '-f',
        type=str,
        choices=['cyclonedx', 'spdxlite', 'csv', 'glc-codequality'],
        default='spdxlite',
        help='Output format (optional - default: spdxlite)',
    )
    p_cnv.add_argument(
        '--input-format', type=str, choices=['plain'], default='plain', help='Input format (optional - default: plain)'
    )

    # Sub-command: component
    p_comp = subparsers.add_parser(
        'component',
        aliases=['comp'],
        description=f'SCANOSS Component commands: {__version__}',
        help='Component support commands',
    )

    comp_sub = p_comp.add_subparsers(
        title='Component Commands',
        dest='subparsercmd',
        description='component sub-commands',
        help='component sub-commands',
    )

    # Component Sub-command: component vulns
    c_vulns = comp_sub.add_parser(
        'vulns',
        aliases=['vulnerabilities', 'vu'],
        description=f'Show Vulnerability details: {__version__}',
        help='Retrieve vulnerabilities for the given components',
    )
    c_vulns.set_defaults(func=comp_vulns)

    # Component Sub-command: component licenses
    c_licenses = comp_sub.add_parser(
        'licenses',
        aliases=['lics'],
        description=f'Show License details: {__version__}',
        help='Retrieve licenses for the given components',
    )
    c_licenses.set_defaults(func=comp_licenses)

    # Component Sub-command: component semgrep
    c_semgrep = comp_sub.add_parser(
        'semgrep',
        aliases=['sp'],
        description=f'Show Semgrep findings: {__version__}',
        help='Retrieve semgrep issues/findings for the given components',
    )
    c_semgrep.set_defaults(func=comp_semgrep)

    # Component Sub-command: component provenance
    c_provenance = comp_sub.add_parser(
        'provenance',
        aliases=['prov', 'prv'],
        description=f'Show GEO Provenance findings: {__version__}',
        help='Retrieve geoprovenance for the given components',
    )
    c_provenance.add_argument(
        '--origin',
        action='store_true',
        help='Retrieve geoprovenance using contributors origin (default: declared origin)',
    )
    c_provenance.set_defaults(func=comp_provenance)

    # Component Sub-command: component search
    c_search = comp_sub.add_parser(
        'search',
        aliases=['sc'],
        description=f'Search component details: {__version__}',
        help='Search for a KB component',
    )
    c_search.add_argument('--input', '-i', type=str, help='Input file name')
    c_search.add_argument('--search', '-s', type=str, help='Generic component search')
    c_search.add_argument('--vendor', '-v', type=str, help='Generic component search')
    c_search.add_argument('--comp', '-c', type=str, help='Generic component search')
    c_search.add_argument('--package', '-p', type=str, help='Generic component search')
    c_search.add_argument('--limit', '-l', type=int, help='Generic component search')
    c_search.add_argument('--offset', '-f', type=int, help='Generic component search')
    c_search.set_defaults(func=comp_search)

    # Component Sub-command: component versions
    c_versions = comp_sub.add_parser(
        'versions',
        aliases=['vs'],
        description=f'Get component version details: {__version__}',
        help='Search for component versions',
    )
    c_versions.add_argument('--input', '-i', type=str, help='Input file name')
    c_versions.add_argument('--purl', '-p', type=str, help='Generic component search')
    c_versions.add_argument('--limit', '-l', type=int, help='Generic component search')
    c_versions.set_defaults(func=comp_versions)

    # Sub-command: crypto
    p_crypto = subparsers.add_parser(
        'crypto',
        aliases=['cr'],
        description=f'SCANOSS Crypto commands: {__version__}',
        help='Crypto support commands',
    )
    crypto_sub = p_crypto.add_subparsers(
        title='Crypto Commands',
        dest='subparsercmd',
        description='crypto sub-commands',
        help='crypto sub-commands',
    )

    # GetAlgorithms and GetAlgorithmsInRange gRPC APIs
    p_crypto_algorithms = crypto_sub.add_parser(
        'algorithms',
        aliases=['alg'],
        description=f'Show Cryptographic algorithms: {__version__}',
        help='Retrieve cryptographic algorithms for the given components',
    )
    p_crypto_algorithms.add_argument(
        '--with-range',
        action='store_true',
        help='Returns the list of versions in the specified range that contains cryptographic algorithms',
    )
    p_crypto_algorithms.set_defaults(func=crypto_algorithms)

    # GetEncryptionHints and GetHintsInRange gRPC APIs
    p_crypto_hints = crypto_sub.add_parser(
        'hints',
        description=f'Show Encryption hints: {__version__}',
        help='Retrieve encryption hints for the given components',
    )
    p_crypto_hints.add_argument(
        '--with-range',
        action='store_true',
        help='Returns the list of versions in the specified range that contains encryption hints',
    )
    p_crypto_hints.set_defaults(func=crypto_hints)

    p_crypto_versions_in_range = crypto_sub.add_parser(
        'versions-in-range',
        aliases=['vr'],
        description=f'Show versions in range: {__version__}',
        help="Given a list of PURLS and version ranges, get a list of versions that do/don't contain crypto algorithms",
    )
    p_crypto_versions_in_range.set_defaults(func=crypto_versions_in_range)

    # Common purl Component sub-command options
    for p in [
        c_vulns,
        c_semgrep,
        c_provenance,
        p_crypto_algorithms,
        p_crypto_hints,
        p_crypto_versions_in_range,
        c_licenses,
    ]:
        p.add_argument('--purl', '-p', type=str, nargs='*', help='Package URL - PURL to process.')
        p.add_argument('--input', '-i', type=str, help='Input file name')

    # Common Component sub-command options
    for p in [
        c_vulns,
        c_search,
        c_versions,
        c_semgrep,
        c_provenance,
        p_crypto_algorithms,
        p_crypto_hints,
        p_crypto_versions_in_range,
        c_licenses,
    ]:
        p.add_argument(
            '--timeout',
            '-M',
            type=int,
            default=DEFAULT_API_TIMEOUT,
            help='Timeout (in seconds) for API communication (optional - default 600)',
        )

    # Sub-command: utils
    p_util = subparsers.add_parser(
        'utils',
        aliases=['ut'],
        description=f'SCANOSS Utility commands: {__version__}',
        help='General utility support commands',
    )

    utils_sub = p_util.add_subparsers(
        title='Utils Commands', dest='subparsercmd', description='utils sub-commands', help='utils sub-commands'
    )

    # Utils Sub-command: utils fast
    p_f_f = utils_sub.add_parser(
        'fast', description=f'Is fast winnowing enabled: {__version__}', help='SCANOSS fast winnowing'
    )
    p_f_f.set_defaults(func=fast)

    # Utils Sub-command: utils certloc
    p_c_loc = utils_sub.add_parser(
        'certloc',
        aliases=['cl'],
        description=f'Show location of Python CA Certs: {__version__}',
        help='Display the location of Python CA Certs',
    )
    p_c_loc.set_defaults(func=utils_certloc)

    # Utils Sub-command: utils cert-download
    p_c_dwnld = utils_sub.add_parser(
        'cert-download',
        aliases=['cdl', 'cert-dl'],
        description=f'Download Server SSL Cert: {__version__}',
        help="Download the specified server's SSL PEM certificate",
    )
    p_c_dwnld.set_defaults(func=utils_cert_download)
    p_c_dwnld.add_argument('--hostname', '-n', required=True, type=str, help='Server hostname to download cert from.')
    p_c_dwnld.add_argument(
        '--port', '-p', required=False, type=int, default=443, help='Server port number (default: 443).'
    )

    # Utils Sub-command: utils pac-proxy
    p_p_proxy = utils_sub.add_parser(
        'pac-proxy',
        aliases=['pac'],
        description=f'Determine Proxy from PAC: {__version__}',
        help='Use Proxy Auto-Config to determine proxy configuration',
    )
    p_p_proxy.set_defaults(func=utils_pac_proxy)
    p_p_proxy.add_argument(
        '--pac',
        required=False,
        type=str,
        default='auto',
        help='Proxy auto configuration. Specify a file, http url or "auto" to try to discover it.',
    )
    p_p_proxy.add_argument(
        '--url',
        required=False,
        type=str,
        default='https://api.osskb.org',
        help='URL to test (default: https://api.osskb.org).',
    )

    p_results = subparsers.add_parser(
        'results',
        aliases=['res'],
        description=f'SCANOSS Results commands: {__version__}',
        help='Process scan results',
    )
    p_results.add_argument(
        'filepath',
        metavar='FILEPATH',
        type=str,
        nargs='?',
        help='Path to the file containing the results',
    )
    p_results.add_argument(
        '--match-type',
        '-mt',
        help='Filter results by match type (comma-separated, e.g., file,snippet)',
    )
    p_results.add_argument(
        '--status',
        '-s',
        help='Filter results by file status (comma-separated, e.g., pending, identified)',
    )
    p_results.add_argument(
        '--has-pending',
        action='store_true',
        help='Filter results to only include files with pending status',
    )
    p_results.add_argument(
        '--output',
        '-o',
        help='Output result file',
    )
    p_results.add_argument(
        '--format',
        '-f',
        choices=['json', 'plain'],
        help='Output format (default: plain)',
    )
    p_results.set_defaults(func=results)

    # =========================================================================
    # INSPECT SUBCOMMAND - Analysis and validation of scan results
    # =========================================================================

    # Main inspect parser - provides tools for analyzing scan results
    p_inspect = subparsers.add_parser(
        'inspect',
        aliases=['insp', 'ins'],
        description=f'Inspect and analyse scan results: {__version__}',
        help='Inspect and analyse scan results',
    )

    # Inspect sub-commands parser
    p_inspect_sub = p_inspect.add_subparsers(
        title='Inspect Commands',
        dest='subparsercmd',
        description='Available inspection sub-commands',
        help='Choose an inspection type',
    )

    # -------------------------------------------------------------------------
    # RAW RESULTS INSPECTION - Analyse raw scan output
    # -------------------------------------------------------------------------

    # Raw results parser - handles inspection of unprocessed scan results
    p_inspect_raw = p_inspect_sub.add_parser(
        'raw',
        description='Inspect and analyse SCANOSS raw scan results',
        help='Analyse raw scan results for various compliance issues',
    )

    # Raw results sub-commands parser
    p_inspect_raw_sub = p_inspect_raw.add_subparsers(
        title='Raw Results Inspection Commands',
        dest='subparser_subcmd',
        description='Tools for analyzing raw scan results',
        help='Choose a raw results analysis type',
    )

    # Copyleft license inspection - identifies copyleft license violations
    p_inspect_raw_copyleft = p_inspect_raw_sub.add_parser(
        'copyleft',
        aliases=['cp'],
        description='Identify components with copyleft licenses that may require compliance action',
        help='Find copyleft license violations',
    )

    # License summary inspection - provides overview of all detected licenses
    p_inspect_raw_license_summary = p_inspect_raw_sub.add_parser(
        'license-summary',
        aliases=['lic-summary', 'licsum'],
        description='Generate comprehensive summary of all licenses found in scan results',
        help='Generate license summary report',
    )

    # Component summary inspection - provides overview of all detected components
    p_inspect_raw_component_summary = p_inspect_raw_sub.add_parser(
        'component-summary',
        aliases=['comp-summary', 'compsum'],
        description='Generate comprehensive summary of all components found in scan results',
        help='Generate component summary report',
    )

    # Undeclared components inspection - finds components not declared in SBOM
    p_inspect_raw_undeclared = p_inspect_raw_sub.add_parser(
        'undeclared',
        aliases=['un'],
        description='Identify components present in code but not declared in SBOM files',
        help='Find undeclared components',
    )
    # SBOM format option for undeclared components inspection
    p_inspect_raw_undeclared.add_argument(
        '--sbom-format',
        required=False,
        choices=['legacy', 'settings'],
        default='settings',
        help='SBOM format type for comparison: legacy or settings (default)',
    )

    # -------------------------------------------------------------------------
    # BACKWARD COMPATIBILITY - Support old inspect command format
    # -------------------------------------------------------------------------

    # Legacy copyleft inspection - backward compatibility for 'scanoss-py inspect copyleft'
    p_inspect_legacy_copyleft = p_inspect_sub.add_parser(
        'copyleft',
        aliases=['cp'],
        description='Identify components with copyleft licenses that may require compliance action',
        help='Find copyleft license violations (legacy format)',
    )

    # Legacy undeclared components inspection - backward compatibility for 'scanoss-py inspect undeclared'
    p_inspect_legacy_undeclared = p_inspect_sub.add_parser(
        'undeclared',
        aliases=['un'],
        description='Identify components present in code but not declared in SBOM files',
        help='Find undeclared components (legacy format)',
    )

    # SBOM format option for legacy undeclared components inspection
    p_inspect_legacy_undeclared.add_argument(
        '--sbom-format',
        required=False,
        choices=['legacy', 'settings'],
        default='settings',
        help='SBOM format type for comparison: legacy or settings (default)',
    )

    # Legacy license summary inspection - backward compatibility for 'scanoss-py inspect license-summary'
    p_inspect_legacy_license_summary = p_inspect_sub.add_parser(
        'license-summary',
        aliases=['lic-summary', 'licsum'],
        description='Generate comprehensive summary of all licenses found in scan results',
        help='Generate license summary report (legacy format)',
    )

    # Legacy component summary inspection - backward compatibility for 'scanoss-py inspect component-summary'
    p_inspect_legacy_component_summary = p_inspect_sub.add_parser(
        'component-summary',
        aliases=['comp-summary', 'compsum'],
        description='Generate comprehensive summary of all components found in scan results',
        help='Generate component summary report (legacy format)',
    )

    # Applies the same configuration to both legacy and raw versions
    # License filtering options - common to (legacy) copyleft and license summary commands
    for p in [
        p_inspect_raw_copyleft,
        p_inspect_raw_license_summary,
        p_inspect_legacy_copyleft,
        p_inspect_legacy_license_summary,
    ]:
        p.add_argument('--include', help='Additional licenses to include in analysis (comma-separated list)')
        p.add_argument('--exclude', help='Licenses to exclude from analysis (comma-separated list)')
        p.add_argument('--explicit', help='Use only these specific licenses for analysis (comma-separated list)')

    # License source filtering
    for p in [p_inspect_raw_copyleft, p_inspect_legacy_copyleft]:
        p.add_argument(
            '-ls', '--license-sources',
            action='extend',
            nargs='+',
            choices=VALID_LICENSE_SOURCES,
            help=f'Specify which license sources to check for copyleft violations. Each license object in scan results '
                 f'has a source field indicating its origin. Default: {", ".join(DEFAULT_COPYLEFT_LICENSE_SOURCES)}',
        )

    # Common options for (legacy) copyleft and undeclared component inspection
    for p in [p_inspect_raw_copyleft, p_inspect_raw_undeclared, p_inspect_legacy_copyleft, p_inspect_legacy_undeclared]:
        p.add_argument('-i', '--input', nargs='?', help='Path to scan results file to analyse')
        p.add_argument(
            '-f',
            '--format',
            required=False,
            choices=['json', 'md', 'jira_md'],
            default='json',
            help='Output format: json (default), md (Markdown), or jira_md (JIRA Markdown)',
        )
        p.add_argument('-o', '--output', type=str, help='Save detailed results to specified file')
        p.add_argument('-s', '--status', type=str, help='Save summary status report to Markdown file')

    # Common options for (legacy) license and component summary commands
    for p in [
        p_inspect_raw_license_summary,
        p_inspect_raw_component_summary,
        p_inspect_legacy_license_summary,
        p_inspect_legacy_component_summary,
    ]:
        p.add_argument('-i', '--input', nargs='?', help='Path to scan results file to analyse')
        p.add_argument('-o', '--output', type=str, help='Save summary report to specified file')

    # -------------------------------------------------------------------------
    # DEPENDENCY TRACK INSPECTION - Analyse Dependency Track project data
    # -------------------------------------------------------------------------

    # Dependency Track parser - handles inspection of DT project status and violations
    p_dep_track_sub = p_inspect_sub.add_parser(
        'dependency-track',
        aliases=['dt'],
        description='Inspect and analyse Dependency Track project status and policy violations',
        help='Analyse Dependency Track projects',
    )

    # Dependency Track sub-commands parser
    p_inspect_dep_track_sub = p_dep_track_sub.add_subparsers(
        title='Dependency Track Inspection Commands',
        dest='subparser_subcmd',
        description='Tools for analysing Dependency Track project data',
        help='Choose a Dependency Track analysis type',
    )

    # Project violations inspection - analyses policy violations in DT projects
    p_inspect_dt_project_violation = p_inspect_dep_track_sub.add_parser(
        'project-violations',
        aliases=['pv'],
        description='Analyse policy violations and compliance issues in Dependency Track projects',
        help='Inspect project policy violations',
    )
    # Dependency Track connection and authentication options
    p_inspect_dt_project_violation.add_argument(
        '--url', required=True, type=str, help='Dependency Track server base URL (e.g., https://dtrack.example.com)'
    )
    p_inspect_dt_project_violation.add_argument(
        '--upload-token',
        '-ut',
        required=False,
        type=str,
        help='Project-specific upload token for accessing DT project data',
    )
    p_inspect_dt_project_violation.add_argument(
        '--project-id', '-pid', required=False, type=str, help='Dependency Track project UUID to inspect'
    )
    p_inspect_dt_project_violation.add_argument(
        '--apikey', '-k', required=True, type=str, help='Dependency Track API key for authentication'
    )
    p_inspect_dt_project_violation.add_argument(
        '--project-name', '-pn', required=False, type=str, help='Dependency Track project name'
    )
    p_inspect_dt_project_violation.add_argument(
        '--project-version', '-pv', required=False, type=str, help='Dependency Track project version'
    )
    p_inspect_dt_project_violation.add_argument(
        '--output', '-o', required=False, type=str, help='Save inspection results to specified file'
    )
    p_inspect_dt_project_violation.add_argument(
        '--status', required=False, type=str, help='Save summary status report to specified file'
    )
    p_inspect_dt_project_violation.add_argument(
        '--format',
        '-f',
        required=False,
        choices=['json', 'md', 'jira_md'],
        default='json',
        help='Output format: json (default), md (Markdown) or jira_md (JIRA Markdown)',
    )
    p_inspect_dt_project_violation.add_argument(
        '--timeout',
        '-M',
        required=False,
        default=300,
        type=float,
        help='Timeout (in seconds) for API communication (optional - default 300 sec)',
    )

    # ==============================================================================
    # GitLab Integration Parser
    # ==============================================================================
    # Main parser for GitLab-specific inspection commands and report generation
    p_gitlab_sub = p_inspect_sub.add_parser(
        'gitlab',
        aliases=['glc'],
        description='Generate GitLab-compatible reports from SCANOSS scan results (Markdown summaries)',
        help='Generate GitLab integration reports',
    )

    # GitLab sub-commands parser
    # Provides access to different GitLab report formats and inspection tools
    p_gitlab_sub_parser = p_gitlab_sub.add_subparsers(
        title='GitLab Report Types',
        dest='subparser_subcmd',
        description='Available GitLab report formats for scan result analysis',
        help='Select the type of GitLab report to generate',
    )

    # ==============================================================================
    # GitLab Matches Summary Command
    # ==============================================================================
    # Analyzes scan results and generates a GitLab-compatible Markdown summary
    p_gl_inspect_matches = p_gitlab_sub_parser.add_parser(
        'matches',
        aliases=['ms'],
        description='Generate a Markdown summary report of scan matches for GitLab integration',
        help='Generate Markdown summary report of scan matches',
    )

    # Input file argument - SCANOSS scan results in JSON format
    p_gl_inspect_matches.add_argument(
        '-i', '--input', required=True, type=str, help='Path to SCANOSS scan results file (JSON format) to analyze'
    )

    # Line range prefix for GitLab file navigation
    # Enables clickable file references in the generated report that link to specific lines in GitLab
    p_gl_inspect_matches.add_argument(
        '-lpr',
        '--line-range-prefix',
        required=True,
        type=str,
        help='Base URL prefix for GitLab file links with line ranges (e.g., https://gitlab.com/org/project/-/blob/main)',
    )

    # Output file argument - where to save the generated Markdown report
    p_gl_inspect_matches.add_argument(
        '--output',
        '-o',
        required=False,
        type=str,
        help='Output file path for the generated Markdown report (default: stdout)',
    )

    # TODO Move to the command call def location
    # RAW results
    p_inspect_raw_undeclared.set_defaults(func=inspect_undeclared)
    p_inspect_raw_copyleft.set_defaults(func=inspect_copyleft)
    p_inspect_raw_license_summary.set_defaults(func=inspect_license_summary)
    p_inspect_raw_component_summary.set_defaults(func=inspect_component_summary)
    # Legacy backward compatibility commands
    p_inspect_legacy_copyleft.set_defaults(func=inspect_copyleft)
    p_inspect_legacy_undeclared.set_defaults(func=inspect_undeclared)
    p_inspect_legacy_license_summary.set_defaults(func=inspect_license_summary)
    p_inspect_legacy_component_summary.set_defaults(func=inspect_component_summary)
    # Dependency Track
    p_inspect_dt_project_violation.set_defaults(func=inspect_dep_track_project_violations)
    # GitLab
    p_gl_inspect_matches.set_defaults(func=inspect_gitlab_matches)

    # =========================================================================
    # END INSPECT SUBCOMMAND CONFIGURATION
    # =========================================================================

    # Sub-command: export
    p_export = subparsers.add_parser(
        'export',
        aliases=['exp'],
        description=f'Export SBOM files to external platforms: {__version__}',
        help='Export SBOM files to external platforms',
    )

    export_sub = p_export.add_subparsers(
        title='Export Commands',
        dest='subparsercmd',
        description='export sub-commands',
        help='export sub-commands',
    )

    # Export Sub-command: export dt (Dependency Track)
    e_dt = export_sub.add_parser(
        'dt',
        aliases=['dependency-track'],
        description='Export SBOM to Dependency Track',
        help='Upload SBOM files to Dependency Track',
    )
    e_dt.add_argument('-i', '--input', type=str, required=True, help='Input SBOM file (CycloneDX JSON format)')
    e_dt.add_argument('--url', type=str, required=True, help='Dependency Track base URL')
    e_dt.add_argument('--apikey', '-k', type=str, required=True, help='Dependency Track API key')
    e_dt.add_argument('--output', '-o', type=str, help='File to save export token and uuid into')
    e_dt.add_argument('--project-id', '-pid', type=str, help='Dependency Track project UUID')
    e_dt.add_argument('--project-name', '-pn', type=str, help='Dependency Track project name')
    e_dt.add_argument('--project-version', '-pv', type=str, help='Dependency Track project version')
    e_dt.set_defaults(func=export_dt)

    # Sub-command: folder-scan
    p_folder_scan = subparsers.add_parser(
        'folder-scan',
        aliases=['fs'],
        description=f'Scan the given directory using folder hashing: {__version__}',
        help='Scan the given directory using folder hashing',
    )
    p_folder_scan.add_argument('scan_dir', metavar='FILE/DIR', type=str, nargs='?', help='The root directory to scan')
    p_folder_scan.add_argument(
        '--timeout',
        '-M',
        type=int,
        default=600,
        help='Timeout (in seconds) for API communication (optional - default 600)',
    )
    p_folder_scan.add_argument(
        '--format',
        '-f',
        type=str,
        choices=['json', 'cyclonedx'],
        default='json',
        help='Result output format (optional - default: json)',
    )
    p_folder_scan.add_argument(
        '--rank-threshold',
        type=int,
        default=DEFAULT_HFH_RANK_THRESHOLD,
        help='Filter results to only show those with rank value at or below this threshold (e.g., --rank-threshold 3 '
        'returns results with rank 1, 2, or 3). Lower rank values indicate higher quality matches.',
    )
    p_folder_scan.add_argument(
        '--depth',
        type=int,
        default=DEFAULT_HFH_DEPTH,
        help=f'Defines how deep to scan the root directory (optional - default {DEFAULT_HFH_DEPTH})',
    )
    p_folder_scan.add_argument(
        '--recursive-threshold',
        type=float,
        default=DEFAULT_HFH_RECURSIVE_THRESHOLD,
        help=f'Minimum score threshold to consider a match (optional - default: {DEFAULT_HFH_RECURSIVE_THRESHOLD})',
    )
    p_folder_scan.add_argument(
        '--min-accepted-score',
        type=float,
        default=DEFAULT_HFH_MIN_ACCEPTED_SCORE,
        help=(
            'Only show results with a score at or above this threshold '
            f'(optional - default: {DEFAULT_HFH_MIN_ACCEPTED_SCORE})'
        ),
    )
    p_folder_scan.set_defaults(func=folder_hashing_scan)

    # Sub-command: folder-hash
    p_folder_hash = subparsers.add_parser(
        'folder-hash',
        aliases=['fh'],
        description=f'Produce a folder hash for the given directory: {__version__}',
        help='Produce a folder hash for the given directory',
    )
    p_folder_hash.add_argument('scan_dir', metavar='FILE/DIR', type=str, nargs='?', help='A file or folder to scan')
    p_folder_hash.add_argument(
        '--format',
        '-f',
        type=str,
        choices=['json'],
        default='json',
        help='Result output format (optional - default: json)',
    )
    p_folder_hash.add_argument(
        '--depth',
        type=int,
        default=DEFAULT_HFH_DEPTH,
        help=f'Defines how deep to hash the root directory (optional - default {DEFAULT_HFH_DEPTH})',
    )
    p_folder_hash.set_defaults(func=folder_hash)

    # Sub-command: delta
    p_delta = subparsers.add_parser(
        'delta',
        aliases=['dl'],
        description=f'SCANOSS Delta commands: {__version__}',
        help='Delta support commands',
    )

    delta_sub = p_delta.add_subparsers(
        title='Delta Commands', dest='subparsercmd', description='Delta sub-commands', help='Delta sub-commands'
    )

    # Delta Sub-command: copy
    p_copy = delta_sub.add_parser(
        'copy',
        aliases=['cp'],
        description=f'Copy file list into delta dir: {__version__}',
        help='Copy the given list of files into a delta directory',
    )
    p_copy.add_argument('--input', '-i', type=str, required=True, help='Input file with diff list')
    p_copy.add_argument('--folder', '-fd', type=str, help='Delta folder to copy into')
    p_copy.add_argument('--root', '-rd', type=str, help='Root directory to place delta folder')
    p_copy.set_defaults(func=delta_copy)

    # Output options
    for p in [
        p_scan,
        p_cs,
        p_wfp,
        p_dep,
        p_fc,
        p_cnv,
        c_vulns,
        c_search,
        c_versions,
        c_semgrep,
        c_provenance,
        p_c_dwnld,
        p_folder_scan,
        p_folder_hash,
        p_crypto_algorithms,
        p_crypto_hints,
        p_crypto_versions_in_range,
        c_licenses,
        p_copy,
    ]:
        p.add_argument('--output', '-o', type=str, help='Output result file name (optional - default stdout).')

    # Format options
    for p in [p_scan, p_cs]:
        choices = ['plain', 'cyclonedx', 'spdxlite', 'csv']
        if p is p_cs:
            choices.append('raw')

        p.add_argument(
            '--format',
            '-f',
            type=str,
            choices=choices,
            default='plain',
            help='Result output format (optional - default: plain)',
        )

    # Scanoss settings options
    for p in [p_folder_scan, p_scan, p_wfp, p_folder_hash]:
        p.add_argument(
            '--settings',
            '-st',
            type=str,
            help='Settings file to use for scanning (optional - default scanoss.json)',
        )
        p.add_argument(
            '--skip-settings-file',
            '-stf',
            action='store_true',
            help='Skip default settings file (scanoss.json) if it exists',
        )

    # Global Scan command options
    for p in [p_scan, p_cs]:
        p.add_argument(
            '--apiurl', type=str, help='SCANOSS API base URL (optional - default: https://api.osskb.org)'
        )

    # Global Scan/Fingerprint filter options
    for p in [p_scan, p_wfp]:
        p.add_argument('--obfuscate', action='store_true', help='Obfuscate fingerprints')
        p.add_argument('--all-extensions', action='store_true', help='Fingerprint all file extensions/types...')
        p.add_argument('--all-folders', action='store_true', help='Fingerprint all folders...')
        p.add_argument('--all-hidden', action='store_true', help='Fingerprint all hidden files/folders...')
        p.add_argument('--hpsm', '-H', action='store_true', help='Use High Precision Snippet Matching algorithm.')
        p.add_argument('--skip-snippets', '-S', action='store_true', help='Skip the generation of snippets')
        p.add_argument('--skip-extension', '-E', type=str, action='append', help='File Extension to skip.')
        p.add_argument('--skip-folder', '-O', type=str, action='append', help='Folder to skip.')
        p.add_argument(
            '--skip-size',
            '-Z',
            type=int,
            default=0,
            help='Minimum file size to consider for fingerprinting (optional - default 0 bytes [unlimited])',
        )
        p.add_argument('--skip-md5', '-5', type=str, action='append', help='Skip files matching MD5.')
        p.add_argument('--strip-hpsm', '-G', type=str, action='append', help='Strip HPSM string from WFP.')
        p.add_argument('--strip-snippet', '-N', type=str, action='append', help='Strip Snippet ID string from WFP.')
        p.add_argument(
            '--skip-headers',
            '-skh',
            action='store_true',
            help='Skip license headers, comments and imports at the beginning of files.',
        )
        p.add_argument(
            '--skip-headers-limit',
            '-shl',
            type=int,
            default=0,
            help='Maximum number of lines to skip when filtering headers (default: 0 = no limit).',
        )

    # Global Scan/GRPC options
    for p in [
        p_scan,
        c_vulns,
        c_search,
        c_versions,
        c_semgrep,
        c_provenance,
        p_folder_scan,
        p_cs,
        p_crypto_algorithms,
        p_crypto_hints,
        p_crypto_versions_in_range,
        c_licenses,
    ]:
        p.add_argument(
            '--key', '-k', type=str, help='SCANOSS API Key token (optional - not required for default OSSKB URL)'
        )
        p.add_argument(
            '--proxy',
            type=str,
            help='Proxy URL to use for connections (optional). '
            'Can also use the environment variable "HTTPS_PROXY=<ip>:<port>" '
            'and "grcp_proxy=<ip>:<port>" for gRPC',
        )
        p.add_argument(
            '--pac',
            type=str,
            help='Proxy auto configuration (optional). Specify a file, http url or "auto" to try to discover it.',
        )
        p.add_argument(
            '--ca-cert',
            type=str,
            help='Alternative certificate PEM file (optional). '
            'Can also use the environment variable '
            '"REQUESTS_CA_BUNDLE=/path/to/cacert.pem" and '
            '"GRPC_DEFAULT_SSL_ROOTS_FILE_PATH=/path/to/cacert.pem" for gRPC',
        )

    # Global GRPC options
    for p in [
        p_scan,
        c_vulns,
        c_search,
        c_versions,
        c_semgrep,
        c_provenance,
        p_folder_scan,
        p_cs,
        p_crypto_algorithms,
        p_crypto_hints,
        p_crypto_versions_in_range,
        c_licenses,
    ]:
        p.add_argument(
            '--api2url', type=str, help='SCANOSS gRPC API 2.0 URL (optional - default: https://api.osskb.org)'
        )
        p.add_argument(
            '--grpc-proxy',
            type=str,
            help='GRPC Proxy URL to use for connections (optional). '
            'Can also use the environment variable "grcp_proxy=<ip>:<port>"',
        )
        p.add_argument(
            '--header',
            '-hdr',
            action='append',  # This allows multiple -H flags
            type=str,
            help='Headers to be sent on request (e.g., -hdr "Name: Value") - can be used multiple times',
        )
        p.add_argument('--ignore-cert-errors', action='store_true', help='Ignore certificate errors')

    # Syft options
    for p in [p_cs, p_dep]:
        p.add_argument(
            '--syft-command',
            type=str,
            help='Syft command and path if required (optional - default syft).',
            default=DEFAULT_SYFT_COMMAND,
        )
        p.add_argument(
            '--syft-timeout',
            type=int,
            default=DEFAULT_SYFT_TIMEOUT,
            help='Timeout (in seconds) for syft to complete (optional - default 600)',
        )

    # gRPC support options
    for p in [
        c_vulns,
        p_scan,
        p_cs,
        p_crypto_algorithms,
        p_crypto_hints,
        p_crypto_versions_in_range,
        c_semgrep,
        c_provenance,
        c_search,
        c_versions,
        c_licenses,
        p_folder_scan,
    ]:
        p.add_argument('--grpc', action='store_true', default=True, help='Use gRPC (default)')
        p.add_argument('--rest', action='store_true', dest='rest', help='Use REST instead of gRPC')

    # Help/Trace command options
    for p in [
        p_scan,
        p_wfp,
        p_dep,
        p_fc,
        p_cnv,
        p_c_loc,
        p_c_dwnld,
        p_p_proxy,
        c_vulns,
        c_search,
        c_versions,
        c_semgrep,
        p_results,
        p_inspect_raw_undeclared,
        p_inspect_raw_copyleft,
        p_inspect_raw_license_summary,
        p_inspect_raw_component_summary,
        p_inspect_legacy_copyleft,
        p_inspect_legacy_undeclared,
        p_inspect_legacy_license_summary,
        p_inspect_legacy_component_summary,
        p_inspect_dt_project_violation,
        p_gl_inspect_matches,
        c_provenance,
        p_folder_scan,
        p_folder_hash,
        p_cs,
        p_crypto_algorithms,
        p_crypto_hints,
        p_crypto_versions_in_range,
        c_licenses,
        e_dt,
        p_copy,
    ]:
        p.add_argument(
            '--debug',
            '-d',
            action='store_true',
            default=os.environ.get('SCANOSS_DEBUG', '').lower() == 'true',
            help='Enable debug messages (can also be set via environment variable SCANOSS_DEBUG)',
        )
        p.add_argument('--trace', '-t', action='store_true', help='Enable trace messages, including API posts')
        p.add_argument('--quiet', '-q', action='store_true', help='Enable quiet mode')

    args = parser.parse_args()

    # TODO: Remove this hack once we go back to using REST as default
    # Handle --rest overriding --grpc default
    if hasattr(args, 'rest') and args.rest:
        args.grpc = False

    if args.version:
        ver(parser, args)
        sys.exit(0)
    if not args.subparser:
        parser.print_help()  # No sub command subcommand, print general help
        sys.exit(1)
    elif (
        args.subparser
        in (
            'utils',
            'ut',
            'component',
            'comp',
            'inspect',
            'insp',
            'ins',
            'crypto',
            'cr',
            'export',
            'exp',
            'delta',
            'dl',
        )
    ) and not args.subparsercmd:
        parser.parse_args([args.subparser, '--help'])  # Force utils helps to be displayed
        sys.exit(1)
    elif (
        (args.subparser in 'inspect')
        and (args.subparsercmd in ('raw', 'dt', 'glc', 'gitlab'))
        and (args.subparser_subcmd is None)
    ):
        parser.parse_args([args.subparser, args.subparsercmd, '--help'])  # Force utils helps to be displayed
        sys.exit(1)
    args.func(parser, args)  # Execute the function associated with the sub-command


def ver(*_):
    """
    Run the "ver" sub-command
    :param _: ignored/unused
    """
    print(f'Version: {__version__}')


def fast(*_):
    """
    Run the "fast" sub-command
    :param _: ignored/unused
    """
    print(f'Fast Winnowing: {FAST_WINNOWING}')


def file_count(parser, args):
    """
    Run the "file_count" sub-command
    Parameters
    ----------
        parser: ArgumentParser
            command line parser object
        args: Namespace
            Parsed arguments
    """
    if not args.scan_dir:
        print_stderr('Please specify a folder')
        parser.parse_args([args.subparser, '-h'])
        sys.exit(1)
    if args.output:
        initialise_empty_file(args.output)

    counter = FileCount(
        debug=args.debug,
        quiet=args.quiet,
        trace=args.trace,
        scan_output=args.output,
        hidden_files_folders=args.all_hidden,
    )
    if not os.path.exists(args.scan_dir):
        print_stderr(f'Error: Folder specified does not exist: {args.scan_dir}.')
        sys.exit(1)
    if os.path.isdir(args.scan_dir):
        counter.count_files(args.scan_dir)
    else:
        print_stderr(f'Error: Path specified is not a folder: {args.scan_dir}.')
        sys.exit(1)


def wfp(parser, args):
    """
    Run the "wfp" sub-command
    Parameters
    ----------
        parser: ArgumentParser
            command line parser object
        args: Namespace
            Parsed arguments
    """
    if not args.scan_dir and not args.stdin:
        print_stderr('Please specify a file/folder or STDIN (--stdin)')
        parser.parse_args([args.subparser, '-h'])
        sys.exit(1)
    if args.strip_hpsm and not args.hpsm and not args.quiet:
        print_stderr('Warning: --strip-hpsm option supplied without enabling HPSM (--hpsm). Ignoring.')
    if args.output:
        initialise_empty_file(args.output)

    # Load scan settings
    scan_settings = None
    if not args.skip_settings_file:
        scan_settings = ScanossSettings(debug=args.debug, trace=args.trace, quiet=args.quiet)
        try:
            scan_settings.load_json_file(args.settings, args.scan_dir)
        except ScanossSettingsError as e:
            print_stderr(f'Error: {e}')
            sys.exit(1)

    scan_options = 0 if args.skip_snippets else ScanType.SCAN_SNIPPETS.value  # Skip snippet generation or not
    scanner = Scanner(
        debug=args.debug,
        trace=args.trace,
        quiet=args.quiet,
        obfuscate=args.obfuscate,
        scan_options=scan_options,
        all_extensions=args.all_extensions,
        all_folders=args.all_folders,
        hidden_files_folders=args.all_hidden,
        hpsm=args.hpsm,
        skip_size=args.skip_size,
        skip_extensions=args.skip_extension,
        skip_folders=args.skip_folder,
        skip_md5_ids=args.skip_md5,
        strip_hpsm_ids=args.strip_hpsm,
        strip_snippet_ids=args.strip_snippet,
        scan_settings=scan_settings,
        skip_headers=args.skip_headers,
        skip_headers_limit=args.skip_headers_limit,
    )
    if args.stdin:
        contents = sys.stdin.buffer.read()
        scanner.wfp_contents(args.stdin, contents, args.output)
    elif args.scan_dir:
        if not os.path.exists(args.scan_dir):
            print_stderr(f'Error: File or folder specified does not exist: {args.scan_dir}.')
            sys.exit(1)
        if os.path.isdir(args.scan_dir):
            scanner.wfp_folder(args.scan_dir, args.output)
        elif os.path.isfile(args.scan_dir):
            scanner.wfp_file(args.scan_dir, args.output)
        else:
            print_stderr(f'Error: Path specified is neither a file or a folder: {args.scan_dir}.')
            sys.exit(1)
    else:
        print_stderr('No action found to process')
        sys.exit(1)


def get_scan_options(args):
    """
    Parse the scanning options to determine the correct scan settings
    :param args: cmd args
    :return: Octal code for encoded scanning options
    """
    scan_files = ScanType.SCAN_FILES.value
    scan_snippets = ScanType.SCAN_SNIPPETS.value
    scan_dependencies = 0
    if args.skip_snippets:
        scan_snippets = 0
    if args.dependencies or args.dep:
        scan_dependencies = ScanType.SCAN_DEPENDENCIES.value
    if args.dependencies_only:
        scan_files = scan_snippets = 0
        scan_dependencies = ScanType.SCAN_DEPENDENCIES.value

    scan_options = scan_files + scan_snippets + scan_dependencies

    if args.debug:
        if ScanType.SCAN_FILES.value & scan_options:
            print_stderr('Scan Files')
        if ScanType.SCAN_SNIPPETS.value & scan_options:
            print_stderr('Scan Snippets')
        if ScanType.SCAN_DEPENDENCIES.value & scan_options:
            print_stderr('Scan Dependencies')
    if scan_options <= 0:
        print_stderr(f'Error: No valid scan options configured: {scan_options}')
        sys.exit(1)
    return scan_options


def scan(parser, args):  # noqa: PLR0912, PLR0915
    """
    Run the "scan" sub-command
    Parameters
    ----------
        parser: ArgumentParser
            command line parser object
        args: Namespace
            Parsed arguments
    """
    if not args.scan_dir and not args.wfp and not args.stdin and not args.dep and not args.files:
        print_stderr(
            'Please specify a file/folder, files (--files), fingerprint (--wfp), dependency (--dep), or STDIN (--stdin)'
        )
        parser.parse_args([args.subparser, '-h'])
        sys.exit(1)
    if args.no_wfp_output:
        print_stderr('Warning: --no-wfp-output is deprecated and has no effect. It will be removed in a future version')
    if args.pac and args.proxy:
        print_stderr('Please specify one of --proxy or --pac, not both')
        parser.parse_args([args.subparser, '-h'])
        sys.exit(1)
    if args.identify and args.settings:
        print_stderr('ERROR: Cannot specify both --identify and --settings options.')
        sys.exit(1)
    if args.settings and args.skip_settings_file:
        print_stderr('ERROR: Cannot specify both --settings and --skip-file-settings options.')
        sys.exit(1)
    # Figure out which settings (if any) to load before processing
    scan_settings = None
    if not args.skip_settings_file:
        scan_settings = ScanossSettings(debug=args.debug, trace=args.trace, quiet=args.quiet)
        try:
            if args.identify:
                scan_settings.load_json_file(args.identify, args.scan_dir).set_file_type('legacy').set_scan_type(
                    'identify'
                )
            elif args.ignore:
                scan_settings.load_json_file(args.ignore, args.scan_dir).set_file_type('legacy').set_scan_type(
                    'blacklist'
                )
            else:
                scan_settings.load_json_file(args.settings, args.scan_dir).set_file_type('new')

        except ScanossSettingsError as e:
            print_stderr(f'Error: {e}')
            sys.exit(1)
    if args.dep:
        if not os.path.exists(args.dep) or not os.path.isfile(args.dep):
            print_stderr(f'Specified --dep file does not exist or is not a file: {args.dep}')
            sys.exit(1)
        result = validate_json_file(args.dep)
        if not result.is_valid:
            print_stderr(f'Error: Dependency file is not valid: {result.error}')
            sys.exit(1)
    if args.strip_hpsm and not args.hpsm and not args.quiet:
        print_stderr('Warning: --strip-hpsm option supplied without enabling HPSM (--hpsm). Ignoring.')

    if args.output:
        initialise_empty_file(args.output)
    output_format = args.format if args.format else 'plain'
    flags = args.flags if args.flags else None
    if args.debug and not args.quiet:
        if args.skip_settings_file:
            print_stderr('Skipping Settings file...')
        if args.all_extensions:
            print_stderr('Scanning all file extensions/types...')
        if args.all_folders:
            print_stderr('Scanning all folders...')
        if args.all_hidden:
            print_stderr('Scanning all hidden files/folders...')
        if args.skip_snippets:
            print_stderr('Skipping snippets...')
        if args.post_size != DEFAULT_POST_SIZE:
            print_stderr(f'Changing scanning POST size to: {args.post_size}k...')
        if args.timeout != DEFAULT_TIMEOUT:
            print_stderr(f'Changing scanning POST timeout to: {args.timeout}...')
        if args.retry != DEFAULT_RETRY:
            print_stderr(f'Changing scanning POST retry to: {args.retry}...')
        if args.obfuscate:
            print_stderr('Obfuscating file fingerprints...')
        if args.proxy:
            print_stderr(f'Using Proxy {args.proxy}...')
        if args.grpc_proxy:
            print_stderr(f'Using GRPC Proxy {args.grpc_proxy}...')
        if args.pac:
            print_stderr(f'Using Proxy Auto-config (PAC) {args.pac}...')
        if args.ca_cert:
            print_stderr(f'Using Certificate {args.ca_cert}...')
        if args.hpsm:
            print_stderr('Setting HPSM mode...')
        if flags:
            print_stderr(f'Using flags {flags}...')
    elif not args.quiet:
        if args.timeout < MIN_TIMEOUT:
            print_stderr(f'POST timeout (--timeout) too small: {args.timeout}. Reverting to default.')
        if args.retry < 0:
            print_stderr(f'POST retry (--retry) too small: {args.retry}. Reverting to default.')

    if args.ca_cert and not os.path.exists(args.ca_cert):
        print_stderr(f'Error: Certificate file does not exist: {args.ca_cert}.')
        sys.exit(1)
    pac_file = get_pac_file(args.pac)
    scan_options = get_scan_options(args)  # Figure out what scanning options we have

    scanner = Scanner(
        debug=args.debug,
        trace=args.trace,
        quiet=args.quiet,
        api_key=args.key,
        url=args.apiurl,
        scan_output=args.output,
        output_format=output_format,
        flags=flags,
        nb_threads=args.threads,
        post_size=args.post_size,
        timeout=args.timeout,
        all_extensions=args.all_extensions,
        all_folders=args.all_folders,
        hidden_files_folders=args.all_hidden,
        scan_options=scan_options,
        sc_timeout=args.sc_timeout,
        sc_command=args.sc_command,
        grpc_url=args.api2url,
        obfuscate=args.obfuscate,
        ignore_cert_errors=args.ignore_cert_errors,
        proxy=args.proxy,
        grpc_proxy=args.grpc_proxy,
        pac=pac_file,
        ca_cert=args.ca_cert,
        retry=args.retry,
        hpsm=args.hpsm,
        skip_size=args.skip_size,
        skip_extensions=args.skip_extension,
        skip_folders=args.skip_folder,
        skip_md5_ids=args.skip_md5,
        strip_hpsm_ids=args.strip_hpsm,
        strip_snippet_ids=args.strip_snippet,
        scan_settings=scan_settings,
        req_headers=process_req_headers(args.header),
        use_grpc=args.grpc,
        skip_headers=args.skip_headers,
        skip_headers_limit=args.skip_headers_limit,
        wfp_output=args.wfp_output,
    )
    if args.wfp:
        if not scanner.is_file_or_snippet_scan():
            print_stderr(f'Error: Cannot specify WFP scanning if file/snippet options are disabled ({scan_options})')
            sys.exit(1)
        if scanner.is_dependency_scan() and not args.dep:
            print_stderr('Error: Cannot specify WFP & Dependency scanning without a dependency file (--dep)')
            sys.exit(1)
        scanner.scan_wfp_with_options(args.wfp, args.dep)
    elif args.stdin:
        contents = sys.stdin.buffer.read()
        if not scanner.scan_contents(args.stdin, contents):
            sys.exit(1)
    elif args.files:
        if not scanner.scan_files_with_options(args.files, args.dep, scanner.winnowing.file_map):
            sys.exit(1)
    elif args.scan_dir:
        if not os.path.exists(args.scan_dir):
            print_stderr(f'Error: File or folder specified does not exist: {args.scan_dir}.')
            sys.exit(1)
        if os.path.isdir(args.scan_dir):
            if not scanner.scan_folder_with_options(
                args.scan_dir,
                args.dep,
                scanner.winnowing.file_map,
                args.dep_scope,
                args.dep_scope_inc,
                args.dep_scope_exc,
            ):
                sys.exit(1)
        elif os.path.isfile(args.scan_dir):
            if not scanner.scan_file_with_options(
                args.scan_dir,
                args.dep,
                scanner.winnowing.file_map,
                args.dep_scope,
                args.dep_scope_inc,
                args.dep_scope_exc,
            ):
                sys.exit(1)
        else:
            print_stderr(f'Error: Path specified is neither a file or a folder: {args.scan_dir}.')
            sys.exit(1)
    elif args.dep:
        if not args.dependencies_only:
            print_stderr(
                'Error: No file or folder specified to scan.'
                ' Please add --dependencies-only to decorate dependency file only.'
            )
            sys.exit(1)
        if not scanner.scan_folder_with_options(
            '.', args.dep, scanner.winnowing.file_map, args.dep_scope, args.dep_scope_inc, args.dep_scope_exc
        ):
            sys.exit(1)
    else:
        print_stderr('No action found to process')
        sys.exit(1)


def dependency(parser, args):
    """
    Run the "dependency" sub-command
    Parameters
    ----------
        parser: ArgumentParser
            command line parser object
        args: Namespace
            Parsed arguments
    """
    if not args.scan_loc and not args.container:
        print_stderr('Please specify a file/folder or container image')
        parser.parse_args([args.subparser, '-h'])
        sys.exit(1)

    # Workaround to return syft scan results converted to our dependency output format
    if args.container:
        args.scan_loc = args.container
        return container_scan(parser, args, only_interim_results=True)

    if not os.path.exists(args.scan_loc):
        print_stderr(f'Error: File or folder specified does not exist: {args.scan_loc}.')
        sys.exit(1)
    if args.output:
        initialise_empty_file(args.output)

    sc_deps = ScancodeDeps(
        debug=args.debug, quiet=args.quiet, trace=args.trace, sc_command=args.sc_command, timeout=args.sc_timeout
    )
    if not sc_deps.get_dependencies(what_to_scan=args.scan_loc, result_output=args.output):
        sys.exit(1)
    return None


def convert(parser, args):
    """
    Run the "convert" sub-command
    Parameters
    ----------
        parser: ArgumentParser
            command line parser object
        args: Namespace
            Parsed arguments
    """
    if not args.input:
        print_stderr('Please specify an input file to convert')
        parser.parse_args([args.subparser, '-h'])
        sys.exit(1)
    success = False
    if args.format == 'cyclonedx':
        if not args.quiet:
            print_stderr('Producing CycloneDX report...')
        cdx = CycloneDx(debug=args.debug, output_file=args.output)
        success = cdx.produce_from_file(args.input)
    elif args.format == 'spdxlite':
        if not args.quiet:
            print_stderr('Producing SPDX Lite report...')
        spdxlite = SpdxLite(debug=args.debug, output_file=args.output)
        success = spdxlite.produce_from_file(args.input)
    elif args.format == 'csv':
        if not args.quiet:
            print_stderr('Producing CSV report...')
        csvo = CsvOutput(debug=args.debug, output_file=args.output)
        success = csvo.produce_from_file(args.input)
    elif args.format == 'glc-codequality':
        if not args.quiet:
            print_stderr('Producing GitLab code quality report...')
        glc_code_quality = GitLabQualityReport(debug=args.debug, trace=args.trace, quiet=args.quiet)
        success = glc_code_quality.produce_from_file(args.input, output_file=args.output)
    else:
        print_stderr(f'ERROR: Unknown output format (--format): {args.format}')
    if not success:
        sys.exit(1)


# =============================================================================
# INSPECT COMMAND HANDLERS - Functions that execute inspection operations
# =============================================================================


def inspect_copyleft(parser, args):
    """
    Handle copyleft license inspection command.

    Analyses scan results to identify components using copyleft licenses
    that may require compliance actions such as source code disclosure.

    Parameters
    ----------
    parser : ArgumentParser
        Command line parser object for help display
    args : Namespace
        Parsed command line arguments containing:
        - input: Path to scan results file
        - output: Optional output file path
        - status: Optional status summary file path
        - format: Output format (json, md, jira_md)
        - include/exclude/explicit: License filter options
    """
    # Validate required input file parameter
    if args.input is None:
        print_stderr('ERROR: Input file is required for copyleft inspection')
        parser.parse_args([args.subparser, args.subparsercmd, args.subparser_subcmd, '-h'])
        sys.exit(1)
    # Initialise output file if specified
    if args.output:
        initialise_empty_file(args.output)
    # Initialise status summary file if specified
    if args.status:
        initialise_empty_file(args.status)
    try:
        # Create and configure copyleft inspector
        i_copyleft = Copyleft(
            debug=args.debug,
            trace=args.trace,
            quiet=args.quiet,
            filepath=args.input,
            format_type=args.format,
            status=args.status,
            output=args.output,
            include=args.include,  # Additional licenses to check
            exclude=args.exclude,  # Licenses to ignore
            explicit=args.explicit,  # Explicit license list
            license_sources=args.license_sources,  # License sources to check (list)
        )
        # Execute inspection and exit with appropriate status code
        status, _ = i_copyleft.run()
        sys.exit(status)
    except Exception as e:
        print_stderr(e)
        if args.debug:
            traceback.print_exc()
        sys.exit(1)


def inspect_undeclared(parser, args):
    """
    Handle undeclared components inspection command.

    Analyses scan results to identify components that are present in the
    codebase but not declared in SBOM or manifest files, which may indicate
    security or compliance risks.

    Parameters
    ----------
    parser : ArgumentParser
        Command line parser object for help display
    args : Namespace
        Parsed command line arguments containing:
        - input: Path to scan results file
        - output: Optional output file path
        - status: Optional status summary file path
        - format: Output format (json, md, jira_md)
        - sbom_format: SBOM format type (legacy, settings)
    """
    # Validate required input file parameter
    if args.input is None:
        print_stderr('ERROR: Input file is required for undeclared component inspection')
        parser.parse_args([args.subparser, args.subparsercmd, args.subparser_subcmd, '-h'])
        sys.exit(1)

    # Initialise output file if specified
    if args.output:
        initialise_empty_file(args.output)

    # Initialise status summary file if specified
    if args.status:
        initialise_empty_file(args.status)

    try:
        # Create and configure undeclared component inspector
        i_undeclared = UndeclaredComponent(
            debug=args.debug,
            trace=args.trace,
            quiet=args.quiet,
            filepath=args.input,
            format_type=args.format,
            status=args.status,
            output=args.output,
            sbom_format=args.sbom_format,  # Format for SBOM comparison
        )

        # Execute inspection and exit with appropriate status code
        status, _ = i_undeclared.run()
        sys.exit(status)
    except Exception as e:
        print_stderr(e)
        if args.debug:
            traceback.print_exc()
        sys.exit(1)


def inspect_license_summary(parser, args):
    """
    Handle license summary inspection command.

    Generates comprehensive summary of all licenses detected in scan results,
    including license counts, risk levels, and compliance recommendations.

    Parameters
    ----------
    parser : ArgumentParser
        Command line parser object for help display
    args : Namespace
        Parsed command line arguments containing:
        - input: Path to scan results file
        - output: Optional output file path
        - include/exclude/explicit: License filter options
    """
    # Validate required input file parameter
    if args.input is None:
        print_stderr('ERROR: Input file is required for license summary')
        parser.parse_args([args.subparser, args.subparsercmd, args.subparser_subcmd, '-h'])
        sys.exit(1)

    # Initialise output file if specified
    if args.output:
        initialise_empty_file(args.output)

    # Create and configure license summary generator
    i_license_summary = LicenseSummary(
        debug=args.debug,
        trace=args.trace,
        quiet=args.quiet,
        filepath=args.input,
        output=args.output,
        include=args.include,  # Additional licenses to include
        exclude=args.exclude,  # Licenses to exclude from summary
        explicit=args.explicit,  # Explicit license list to summarize
    )
    try:
        # Execute summary generation
        i_license_summary.run()
    except Exception as e:
        print_stderr(e)
        if args.debug:
            traceback.print_exc()
        sys.exit(1)


def inspect_component_summary(parser, args):
    """
    Handle component summary inspection command.

    Generates a comprehensive summary of all components detected in scan results,
    including component counts, versions, match types, and security information.

    Parameters
    ----------
    parser : ArgumentParser
        Command line parser object for help display
    args : Namespace
        Parsed command line arguments containing:
        - input: Path to scan results file
        - output: Optional output file path
    """
    # Validate required input file parameter
    if args.input is None:
        print_stderr('ERROR: Input file is required for component summary')
        parser.parse_args([args.subparser, args.subparsercmd, args.subparser_subcmd, '-h'])
        sys.exit(1)

    # Initialise an output file if specified
    if args.output:
        initialise_empty_file(args.output)  # Create/clear output file

    # Create and configure component summary generator
    i_component_summary = ComponentSummary(
        debug=args.debug,
        trace=args.trace,
        quiet=args.quiet,
        filepath=args.input,
        output=args.output,
    )

    try:
        # Execute summary generation
        i_component_summary.run()
    except Exception as e:
        print_stderr(e)
        if args.debug:
            traceback.print_exc()
        sys.exit(1)


def inspect_dep_track_project_violations(parser, args):
    """
    Handle Dependency Track project inspection command.

    Analyses Dependency Track projects for policy violations, security issues,
    and compliance status. Connects to DT API to retrieve project data and
    generate detailed violation reports.

    Parameters
    ----------
    parser : ArgumentParser
        Command line parser object for help display
    args : Namespace
        Parsed command line arguments containing:
        - url: Dependency Track base URL
        - apikey: API key for authentication
        - project_id: Project UUID to inspect
        - project_name: Project name to inspect
        - project_version: Project version to inspect
        - upload_token: Upload token for project access
        - output: Optional output file path
        - format: Output format (json, md)
        - timeout: Optional timeout for API requests

    """
    # Make sure we have project id/project name and version
    _dt_args_validator(parser, args)
    # Initialise the output file if specified
    if args.output:
        initialise_empty_file(args.output)
    # Create and configure Dependency Track inspector
    try:
        dt_proj_violations = DependencyTrackProjectViolationPolicyCheck(
            debug=args.debug,
            trace=args.trace,
            quiet=args.quiet,
            output=args.output,
            status=args.status,
            format_type=args.format,
            url=args.url,  # DT server URL
            api_key=args.apikey,  # Authentication key
            project_id=args.project_id,  # Target project UUID
            upload_token=args.upload_token,  # Upload access token
            project_name=args.project_name,  # DT project name
            project_version=args.project_version,  # DT project version
            timeout=args.timeout,
        )
        # Execute inspection and exit with appropriate status code
        status = dt_proj_violations.run()
        sys.exit(status)
    except Exception as e:
        print_stderr(e)
        if args.debug:
            traceback.print_exc()
        sys.exit(1)


def inspect_gitlab_matches(parser, args):
    """
    Handle GitLab matches the summary inspection command.

    Analyzes SCANOSS scan results and generates a GitLab-compatible Markdown summary
    report of component matches. The report includes match details, file locations,
    and optionally clickable links to source files in GitLab repositories.

    This command processes SCANOSS scan output and creates human-readable Markdown.

    Parameters
    ----------
    parser : ArgumentParser
        Command line parser object for help display
    args : Namespace
        Parsed command line arguments containing:
        - input: Path to SCANOSS scan results file (JSON format) to analyze
        - line_range_prefix: Base URL prefix for generating GitLab file links with line ranges
                            (e.g., 'https://gitlab.com/org/project/-/blob/main')
        - output: Optional output file path for the generated Markdown report (default: stdout)
        - debug: Enable debug output for troubleshooting
        - trace: Enable trace-level logging
        - quiet: Suppress informational messages

    Notes
    -----
    - The output is formatted in Markdown for optimal display in GitLab
    - Line range prefix enables clickable file references in the report
    - If output is not specified, the report is written to stdout
    """

    if args.input is None:
        parser.parse_args([args.subparser, '-h'])
        sys.exit(1)

    if args.line_range_prefix is None:
        parser.parse_args([args.subparser, '-h'])
        sys.exit(1)

    # Initialize output file if specified (create/truncate)
    if args.output:
        initialise_empty_file(args.output)

    try:
        # Create GitLab matches summary generator with configuration
        match_summary = MatchSummary(
            debug=args.debug,
            trace=args.trace,
            quiet=args.quiet,
            scanoss_results_path=args.input,  # Path to SCANOSS JSON results
            output=args.output,  # Output file path or None for stdout
            line_range_prefix=args.line_range_prefix,  # GitLab URL prefix for file links
        )

        # Execute the summary generation
        match_summary.run()
    except Exception as e:
        # Handle any errors during report generation
        print_stderr(e)
        if args.debug:
            traceback.print_exc()
        sys.exit(1)


# =============================================================================
# END INSPECT COMMAND HANDLERS
# =============================================================================


def export_dt(parser, args):
    """
    Validates and exports a Software Bill of Materials (SBOM) to a Dependency-Track server.

    Parameters:
        parser (argparse.ArgumentParser): The argument parser to validate input arguments.
        args (argparse.Namespace): Parsed arguments passed to the command.

    Raises:
        SystemExit: If argument validation fails or uploading the SBOM to the Dependency-Track server
        is unsuccessful.
    """
    # Make sure we have project id/project name and version
    _dt_args_validator(parser, args)
    if args.output:
        initialise_empty_file(args.output)
        if not args.quiet:
            print_stderr(f'Outputting export data result to: {args.output}')
    try:
        dt_exporter = DependencyTrackExporter(
            url=args.url,
            apikey=args.apikey,
            output=args.output,
            debug=args.debug,
            trace=args.trace,
            quiet=args.quiet,
        )
        success = dt_exporter.upload_sbom_file(
            args.input, args.project_id, args.project_name, args.project_version, args.output
        )
        if not success:
            sys.exit(1)
    except Exception as e:
        print_stderr(f'ERROR: {e}')
        if args.debug:
            traceback.print_exc()
        sys.exit(1)


def _dt_args_validator(parser, args):
    """
    Validates command-line arguments related to project identification.

    Parameters
    ----------
    parser : argparse.ArgumentParser
        An argument parser instance for handling command-line arguments.
    args : argparse.Namespace
        Parsed arguments from the command line containing project-related information.

    Raises
    ------
    SystemExit
        If neither a project ID nor the required combination of project name and
        project version is provided, or if any of the compulsory arguments
        are missing.
    """
    if not args.project_id and not args.project_name and not args.project_version:
        print_stderr(
            'Please specify either a project ID (--project-id) or a project name (--project-name) and '
            'version (--project-version)'
        )
        parser.parse_args([args.subparser, '-h'])
        sys.exit(1)
    if not args.project_id and (not args.project_name or not args.project_version):
        print_stderr('Please supply a project name (--project-name) and version (--project-version)')
        sys.exit(1)


def utils_certloc(*_):
    """
    Run the "utils certloc" sub-command
    :param _: ignored/unused
    """
    import certifi  # noqa: PLC0415,I001

    print(f'CA Cert File: {certifi.where()}')


def utils_cert_download(_, args):  # pylint: disable=PLR0912 # noqa: PLR0912
    """
    Run the "utils cert-download" sub-command
    :param _: ignore/unused
    :param args: Parsed arguments
    """
    import socket  # noqa: PLC0415,I001
    import traceback  # noqa: PLC0415,I001
    from urllib.parse import urlparse  # noqa: PLC0415,I001

    from OpenSSL import SSL, crypto  # noqa: PLC0415,I001

    file = sys.stdout
    if args.output:
        file = open(args.output, 'w')
    parsed_url = urlparse(args.hostname)
    hostname = parsed_url.hostname or args.hostname  # Use the parse hostname, or it None use the supplied one
    port = int(parsed_url.port or args.port)  # Use the parsed port, if not use the supplied one (default 443)
    try:
        if args.debug:
            print_stderr(f'Connecting to {hostname} on {port}...')
        conn = SSL.Connection(SSL.Context(SSL.TLSv1_2_METHOD), socket.socket())
        conn.connect((hostname, port))
        conn.do_handshake()
        certs = conn.get_peer_cert_chain()
        for index, cert in enumerate(certs):
            cert_components = dict(cert.get_subject().get_components())
            if sys.version_info[0] >= PYTHON_MAJOR_VERSION:
                cn = cert_components.get(b'CN')
            else:
                # Fallback for Python versions less than PYTHON_MAJOR_VERSION
                cn = cert_components.get('CN')
            if not args.quiet:
                print_stderr(f'Certificate {index} - CN: {cn}')
            if sys.version_info[0] >= PYTHON_MAJOR_VERSION:
                print(
                    (crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode('utf-8')).strip(), file=file
                )  # Print the downloaded PEM certificate
            else:
                print((crypto.dump_certificate(crypto.FILETYPE_PEM, cert)).strip(), file=file)
    except SSL.Error as e:
        print_stderr(f'ERROR: Exception ({e.__class__.__name__}) Downloading certificate from {hostname}:{port} - {e}.')
        if args.debug:
            traceback.print_exc()
        sys.exit(1)
    else:
        if args.output:
            if args.debug:
                print_stderr(f'Saved certificate to {args.output}')
            file.close()


def utils_pac_proxy(_, args):
    """
    Run the "utils pac-proxy" sub-command
    :param _: ignore/unused
    :param args: Parsed arguments
    """
    from pypac.resolver import ProxyResolver  # noqa: PLC0415,I001

    if not args.pac:
        print_stderr('Error: No pac file option specified.')
        sys.exit(1)
    pac_file = get_pac_file(args.pac)
    if pac_file is None:
        print_stderr(f'No proxy configuration for: {args.pac}')
        sys.exit(1)
    resolver = ProxyResolver(pac_file)
    proxies = resolver.get_proxy_for_requests(args.url)
    print(f'Proxies: {proxies}\n')


def get_pac_file(pac: str):
    """
    Get a PAC file if requested. Load the system version (auto), specific local file, or download URL
    :param pac: PAC file (auto, file://..., http...)
    :return: PAC File object or None
    """
    pac_file = None
    if pac:
        if pac == 'auto':
            pac_file = pypac.get_pac()  # try to determine the PAC file
        elif pac.startswith('file://'):
            pac_local = pac[7:]  # Remove 'file://' prefix (7 characters)
            if not os.path.exists(pac_local):
                print_stderr(f'Error: PAC file does not exist: {pac_local}.')
                sys.exit(1)
            with open(pac_local) as pf:
                pac_file = pypac.get_pac(js=pf.read())
        elif pac.startswith('http'):
            pac_file = pypac.get_pac(url=pac)
        else:
            print_stderr(f'Error: Unknown PAC file option: {pac}. Should be one of "auto", "file://", "https://"')
            sys.exit(1)
    return pac_file


def crypto_algorithms(parser, args):
    """
    Run the "crypto algorithms" sub-command
    Parameters
    ----------
        parser: ArgumentParser
            command line parser object
        args: Namespace
            Parsed arguments
    """
    if (not args.purl and not args.input) or (args.purl and args.input):
        print_stderr('Please specify an input file or purl to decorate (--purl or --input)')
        parser.parse_args([args.subparser, args.subparsercmd, '-h'])
        sys.exit(1)
    if args.ca_cert and not os.path.exists(args.ca_cert):
        print_stderr(f'Error: Certificate file does not exist: {args.ca_cert}.')
        sys.exit(1)

    try:
        config = create_cryptography_config_from_args(args)
        grpc_config = create_grpc_config_from_args(args)
        if args.pac:
            grpc_config.pac = get_pac_file(args.pac)
        if args.header:
            grpc_config.req_headers = process_req_headers(args.header)
        client = ScanossGrpc(**asdict(grpc_config))

        cryptography = Cryptography(config=config, client=client)
        cryptography.get_algorithms()
        cryptography.present(output_file=args.output)
    except ScanossGrpcError as e:
        print_stderr(f'API ERROR: {e}')
        sys.exit(1)
    except Exception as e:
        if args.debug:
            import traceback  # noqa: PLC0415,I001

            traceback.print_exc()
        print_stderr(f'ERROR: {e}')
        sys.exit(1)


def crypto_hints(parser, args):
    """
    Run the "crypto hints" sub-command
    Parameters
    ----------
        parser: ArgumentParser
            command line parser object
        args: Namespace
            Parsed arguments
    """
    if (not args.purl and not args.input) or (args.purl and args.input):
        print_stderr('Please specify an input file or purl to decorate (--purl or --input)')
        parser.parse_args([args.subparser, args.subparsercmd, '-h'])
        sys.exit(1)
    if args.ca_cert and not os.path.exists(args.ca_cert):
        print_stderr(f'Error: Certificate file does not exist: {args.ca_cert}.')
        sys.exit(1)

    try:
        config = create_cryptography_config_from_args(args)
        grpc_config = create_grpc_config_from_args(args)
        if args.pac:
            grpc_config.pac = get_pac_file(args.pac)
        if args.header:
            grpc_config.req_headers = process_req_headers(args.header)
        client = ScanossGrpc(**asdict(grpc_config))

        cryptography = Cryptography(config=config, client=client)
        cryptography.get_encryption_hints()
        cryptography.present(output_file=args.output)
    except ScanossGrpcError as e:
        print_stderr(f'API ERROR: {e}')
        sys.exit(1)
    except Exception as e:
        if args.debug:
            import traceback  # noqa: PLC0415,I001

            traceback.print_exc()
        print_stderr(f'ERROR: {e}')
        sys.exit(1)


def crypto_versions_in_range(parser, args):
    """
    Run the "crypto versions-in-range" sub-command
    Parameters
    ----------
        parser: ArgumentParser
            command line parser object
        args: Namespace
            Parsed arguments
    """
    if (not args.purl and not args.input) or (args.purl and args.input):
        print_stderr('Please specify an input file or purl to decorate (--purl or --input)')
        parser.parse_args([args.subparser, args.subparsercmd, '-h'])
        sys.exit(1)
    if args.ca_cert and not os.path.exists(args.ca_cert):
        print_stderr(f'Error: Certificate file does not exist: {args.ca_cert}.')
        sys.exit(1)

    try:
        config = create_cryptography_config_from_args(args)
        grpc_config = create_grpc_config_from_args(args)
        if args.pac:
            grpc_config.pac = get_pac_file(args.pac)
        if args.header:
            grpc_config.req_headers = process_req_headers(args.header)
        client = ScanossGrpc(**asdict(grpc_config))

        cryptography = Cryptography(config=config, client=client)
        cryptography.get_versions_in_range()
        cryptography.present(output_file=args.output)
    except ScanossGrpcError as e:
        print_stderr(f'API ERROR: {e}')
        sys.exit(1)
    except Exception as e:
        if args.debug:
            import traceback  # noqa: PLC0415,I001

            traceback.print_exc()
        print_stderr(f'ERROR: {e}')
        sys.exit(1)


def comp_vulns(parser, args):
    """
    Run the "component vulns" sub-command
    Parameters
    ----------
        parser: ArgumentParser
            command line parser object
        args: Namespace
            Parsed arguments
    """
    if (not args.purl and not args.input) or (args.purl and args.input):
        print_stderr('Please specify an input file or purl to decorate (--purl or --input)')
        parser.parse_args([args.subparser, args.subparsercmd, '-h'])
        sys.exit(1)
    if args.ca_cert and not os.path.exists(args.ca_cert):
        print_stderr(f'Error: Certificate file does not exist: {args.ca_cert}.')
        sys.exit(1)
    pac_file = get_pac_file(args.pac)
    comps = Components(
        debug=args.debug,
        trace=args.trace,
        quiet=args.quiet,
        grpc_url=args.api2url,
        api_key=args.key,
        ca_cert=args.ca_cert,
        proxy=args.proxy,
        grpc_proxy=args.grpc_proxy,
        pac=pac_file,
        timeout=args.timeout,
        req_headers=process_req_headers(args.header),
        ignore_cert_errors=args.ignore_cert_errors,
        use_grpc=args.grpc,
    )
    if not comps.get_vulnerabilities(args.input, args.purl, args.output):
        sys.exit(1)


def comp_semgrep(parser, args):
    """
    Run the "component semgrep" sub-command
    Parameters
    ----------
        parser: ArgumentParser
            command line parser object
        args: Namespace
            Parsed arguments
    """
    if (not args.purl and not args.input) or (args.purl and args.input):
        print_stderr('Please specify an input file or purl to decorate (--purl or --input)')
        parser.parse_args([args.subparser, args.subparsercmd, '-h'])
        sys.exit(1)
    if args.ca_cert and not os.path.exists(args.ca_cert):
        print_stderr(f'Error: Certificate file does not exist: {args.ca_cert}.')
        sys.exit(1)
    pac_file = get_pac_file(args.pac)
    comps = Components(
        debug=args.debug,
        trace=args.trace,
        quiet=args.quiet,
        grpc_url=args.api2url,
        api_key=args.key,
        ca_cert=args.ca_cert,
        proxy=args.proxy,
        grpc_proxy=args.grpc_proxy,
        pac=pac_file,
        timeout=args.timeout,
        req_headers=process_req_headers(args.header),
        use_grpc=args.grpc,
    )
    if not comps.get_semgrep_details(args.input, args.purl, args.output):
        sys.exit(1)


def comp_search(parser, args):
    """
    Run the "component search" sub-command
    Parameters
    ----------
        parser: ArgumentParser
            command line parser object
        args: Namespace
            Parsed arguments
    """
    if (not args.input and not args.search and not args.vendor and not args.comp) or (
        args.input and (args.search or args.vendor or args.comp)
    ):
        print_stderr('Please specify an input file or search terms (--input or --search, or --vendor or --comp.)')
        parser.parse_args([args.subparser, args.subparsercmd, '-h'])
        sys.exit(1)

    if args.ca_cert and not os.path.exists(args.ca_cert):
        print_stderr(f'Error: Certificate file does not exist: {args.ca_cert}.')
        sys.exit(1)
    pac_file = get_pac_file(args.pac)
    comps = Components(
        debug=args.debug,
        trace=args.trace,
        quiet=args.quiet,
        grpc_url=args.api2url,
        api_key=args.key,
        ca_cert=args.ca_cert,
        proxy=args.proxy,
        grpc_proxy=args.grpc_proxy,
        pac=pac_file,
        timeout=args.timeout,
        req_headers=process_req_headers(args.header),
        use_grpc=args.grpc,
    )
    if not comps.search_components(
        args.output,
        json_file=args.input,
        search=args.search,
        vendor=args.vendor,
        comp=args.comp,
        package=args.package,
        limit=args.limit,
        offset=args.offset,
    ):
        sys.exit(1)


def comp_versions(parser, args):
    """
    Run the "component versions" sub-command
    Parameters
    ----------
        parser: ArgumentParser
            command line parser object
        args: Namespace
            Parsed arguments
    """
    if (not args.input and not args.purl) or (args.input and args.purl):
        print_stderr('Please specify an input file or search terms (--input or --purl.)')
        parser.parse_args([args.subparser, args.subparsercmd, '-h'])
        sys.exit(1)

    if args.ca_cert and not os.path.exists(args.ca_cert):
        print_stderr(f'Error: Certificate file does not exist: {args.ca_cert}.')
        sys.exit(1)
    pac_file = get_pac_file(args.pac)
    comps = Components(
        debug=args.debug,
        trace=args.trace,
        quiet=args.quiet,
        grpc_url=args.api2url,
        api_key=args.key,
        ca_cert=args.ca_cert,
        proxy=args.proxy,
        grpc_proxy=args.grpc_proxy,
        pac=pac_file,
        timeout=args.timeout,
        req_headers=process_req_headers(args.header),
        use_grpc=args.grpc,
    )
    if not comps.get_component_versions(args.output, json_file=args.input, purl=args.purl, limit=args.limit):
        sys.exit(1)


def comp_provenance(parser, args):
    """
    Run the "component provenance" sub-command
    Parameters
    ----------
        parser: ArgumentParser
            command line parser object
        args: Namespace
            Parsed arguments
    """
    if (not args.purl and not args.input) or (args.purl and args.input):
        print_stderr('Please specify an input file or purl to decorate (--purl or --input)')
        parser.parse_args([args.subparser, args.subparsercmd, '-h'])
        sys.exit(1)
    if args.ca_cert and not os.path.exists(args.ca_cert):
        print_stderr(f'Error: Certificate file does not exist: {args.ca_cert}.')
        sys.exit(1)
    pac_file = get_pac_file(args.pac)
    comps = Components(
        debug=args.debug,
        trace=args.trace,
        quiet=args.quiet,
        grpc_url=args.api2url,
        api_key=args.key,
        ca_cert=args.ca_cert,
        proxy=args.proxy,
        grpc_proxy=args.grpc_proxy,
        pac=pac_file,
        timeout=args.timeout,
        req_headers=process_req_headers(args.header),
        use_grpc=args.grpc,
    )
    if not comps.get_provenance_details(args.input, args.purl, args.output, args.origin):
        sys.exit(1)


def comp_licenses(parser, args):
    """
    Run the "component licenses" sub-command
    Parameters
    ----------
        parser: ArgumentParser
            command line parser object
        args: Namespace
            Parsed arguments
    """
    if (not args.purl and not args.input) or (args.purl and args.input):
        print_stderr('ERROR: Please specify an input file or purl to decorate (--purl or --input)')
        parser.parse_args([args.subparser, args.subparsercmd, '-h'])
        sys.exit(1)
    if args.ca_cert and not os.path.exists(args.ca_cert):
        print_stderr(f'ERROR: Certificate file does not exist: {args.ca_cert}.')
        sys.exit(1)
    pac_file = get_pac_file(args.pac)
    comps = Components(
        debug=args.debug,
        trace=args.trace,
        quiet=args.quiet,
        grpc_url=args.api2url,
        api_key=args.key,
        ca_cert=args.ca_cert,
        proxy=args.proxy,
        grpc_proxy=args.grpc_proxy,
        pac=pac_file,
        timeout=args.timeout,
        req_headers=process_req_headers(args.header),
        use_grpc=args.grpc,
    )
    if not comps.get_licenses(args.input, args.purl, args.output):
        sys.exit(1)


def results(parser, args):
    """
    Run the "results" sub-command
    Parameters
    ----------
        parser: ArgumentParser
            command line parser object
        args: Namespace
            Parsed arguments
    """
    if not args.filepath:
        print_stderr('ERROR: Please specify a file containing the results')
        parser.parse_args([args.subparser, '-h'])
        sys.exit(1)

    file_path = Path(args.filepath).resolve()

    if not file_path.is_file():
        print_stderr(f'The specified file {args.filepath} does not exist')
        sys.exit(1)

    results = Results(
        debug=args.debug,
        trace=args.trace,
        quiet=args.quiet,
        filepath=file_path,
        match_type=args.match_type,
        status=args.status,
        output_file=args.output,
        output_format=args.format,
    )

    if args.has_pending:
        results.get_pending_identifications().present()
        if results.has_results():
            sys.exit(1)
    else:
        results.apply_filters().present()


def process_req_headers(headers_array: List[str]) -> dict:
    """
    Process a list of header strings in the format "Name: Value" into a dictionary.

    Args:
        headers_array (list): List of header strings from command line args

    Returns:
        dict: Dictionary of header name-value pairs
    """
    # Check if headers_array is empty
    if not headers_array:
        # Array is empty
        return {}

    dict_headers = {}
    for header_str in headers_array:
        # Split each "Name: Value" header
        parts = header_str.split(':', 1)
        if len(parts) == HEADER_PARTS_COUNT:
            name = parts[0].strip()
            value = parts[1].strip()
            dict_headers[name] = value
    return dict_headers


def folder_hashing_scan(parser, args):
    """Run the "folder-scan" sub-command

    Args:
        parser (ArgumentParser): command line parser object
        args (Namespace): Parsed arguments
    """
    try:
        if not args.scan_dir:
            print_stderr('ERROR: Please specify a directory to scan')
            parser.parse_args([args.subparser, '-h'])
            sys.exit(1)

        if not os.path.exists(args.scan_dir) or not os.path.isdir(args.scan_dir):
            print_stderr(f'ERROR: The specified directory {args.scan_dir} does not exist')
            sys.exit(1)

        scanner_config = create_scanner_config_from_args(args)
        scanoss_settings = get_scanoss_settings_from_args(args)
        grpc_config = create_grpc_config_from_args(args)

        client = ScanossGrpc(**asdict(grpc_config))

        scanner = ScannerHFH(
            scan_dir=args.scan_dir,
            config=scanner_config,
            client=client,
            scanoss_settings=scanoss_settings,
            rank_threshold=args.rank_threshold,
            depth=args.depth,
            recursive_threshold=args.recursive_threshold,
            min_accepted_score=args.min_accepted_score,
            use_grpc=args.grpc,
        )

        if scanner.scan():
            scanner.present(output_file=args.output, output_format=args.format)
    except ScanossGrpcError as e:
        print_stderr(f'ERROR: {e}')
        sys.exit(1)


def folder_hash(parser, args):
    """Run the "folder-hash" sub-command

    Args:
        parser (ArgumentParser): command line parser object
        args (Namespace): Parsed arguments
    """
    try:
        if not args.scan_dir:
            print_stderr('ERROR: Please specify a directory to scan')
            parser.parse_args([args.subparser, '-h'])
            sys.exit(1)

        if not os.path.exists(args.scan_dir) or not os.path.isdir(args.scan_dir):
            print_stderr(f'ERROR: The specified directory {args.scan_dir} does not exist')
            sys.exit(1)

        folder_hasher_config = create_folder_hasher_config_from_args(args)
        scanoss_settings = get_scanoss_settings_from_args(args)

        folder_hasher = FolderHasher(
            scan_dir=args.scan_dir,
            config=folder_hasher_config,
            scanoss_settings=scanoss_settings,
            depth=args.depth,
        )

        folder_hasher.hash_directory(args.scan_dir)
        folder_hasher.present(output_file=args.output, output_format=args.format)
    except Exception as e:
        print_stderr(f'ERROR: {e}')
        sys.exit(1)


def container_scan(parser, args, only_interim_results: bool = False):
    """
    Run the "container-scan" sub-command
    Parameters
    ----------
        parser: ArgumentParser
            command line parser object
        args: Namespace
            Parsed arguments
    """
    if not args.scan_loc:
        print_stderr(
            'Please specify a container image, Docker tar, OCI tar, OCI directory, SIF Container, or directory to scan'
        )
        parser.parse_args([args.subparser, '-h'])
        sys.exit(1)

    try:
        config = create_container_scanner_config_from_args(args)
        config.only_interim_results = only_interim_results
        container_scanner = ContainerScanner(
            config=config,
            what_to_scan=args.scan_loc,
        )

        container_scanner.scan()
        if only_interim_results:
            container_scanner.present(output_file=config.output, output_format='raw')
        else:
            container_scanner.decorate_scan_results_with_dependencies()
            container_scanner.present(output_file=config.output, output_format=config.format)
    except Exception as e:
        print_stderr(f'ERROR: {e}')
        sys.exit(1)


def get_scanoss_settings_from_args(args):
    scanoss_settings = None
    if not args.skip_settings_file:
        scanoss_settings = ScanossSettings(debug=args.debug, trace=args.trace, quiet=args.quiet)
        try:
            scanoss_settings.load_json_file(args.settings, args.scan_dir).set_file_type('new').set_scan_type('identify')
        except ScanossSettingsError as e:
            print_stderr(f'Error: {e}')
            sys.exit(1)
    return scanoss_settings


def initialise_empty_file(filename: str):
    """
    Initialises an empty file with the specified name. If the file already exists,
    it truncates its content. Ensures proper error handling in case of failure.

    Args:
        filename (str): The name of the file to be initialised.

    Raises:
        SystemExit: If the file cannot be created or written due to an exception,
        the function prints an error message and exits the program.

    Note:
        This function writes an empty file and handles exceptions to ensure the
        program does not continue execution in case of an error.
    """
    if filename:
        try:
            open(filename, 'w').close()
        except Exception as e:
            print_stderr(f'Error: Unable to create output file {filename}: {e}')
            sys.exit(1)


def delta_copy(parser, args):
    """
    Handle delta copy command.

    Copies files listed in an input file to a target directory while preserving
    their directory structure. Creates a unique delta directory if none is specified.

    Parameters
    ----------
    parser : ArgumentParser
        Command line parser object for help display
    args : Namespace
        Parsed command line arguments containing:
        - input: Path to file containing list of files to copy
        - folder: Optional target directory path
        - output: Optional output file path
    """
    # Validate required input file parameter
    if args.input is None:
        print_stderr('ERROR: Input file is required for copying')
        parser.parse_args([args.subparser, args.subparsercmd, '-h'])
        sys.exit(1)
    # Initialise output file if specified
    if args.output:
        initialise_empty_file(args.output)
    try:
        # Create and configure delta copy command
        delta = Delta(
            debug=args.debug,
            trace=args.trace,
            quiet=args.quiet,
            filepath=args.input,
            folder=args.folder,
            output=args.output,
            root_dir=args.root,
        )
        # Execute copy and exit with appropriate status code
        status, _ = delta.copy()
        sys.exit(status)
    except Exception as e:
        print_stderr(e)
        if args.debug:
            traceback.print_exc()
        sys.exit(1)


def main():
    """
    Run the ScanOSS CLI
    """
    setup_args()


if __name__ == '__main__':
    main()
