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
from dataclasses import asdict
from pathlib import Path
from typing import List

import pypac

from scanoss.cryptography import Cryptography, create_cryptography_config_from_args
from scanoss.inspection.component_summary import ComponentSummary
from scanoss.inspection.license_summary import LicenseSummary
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
    DEFAULT_HFH_RANK_THRESHOLD,
    DEFAULT_POST_SIZE,
    DEFAULT_RETRY,
    DEFAULT_TIMEOUT,
    MIN_TIMEOUT,
    PYTHON_MAJOR_VERSION,
)
from .csvoutput import CsvOutput
from .cyclonedx import CycloneDx
from .filecount import FileCount
from .inspection.copyleft import Copyleft
from .inspection.undeclared_component import UndeclaredComponent
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
    p_scan.add_argument('--no-wfp-output', action='store_true', help='Skip WFP file generation')
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
        choices=['cyclonedx', 'spdxlite', 'csv'],
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
    for p in [c_vulns, c_semgrep, c_provenance, p_crypto_algorithms, p_crypto_hints, p_crypto_versions_in_range]:
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

    ########################################### INSPECT SUBCOMMAND ###########################################
    # Sub-command: inspect
    p_inspect = subparsers.add_parser(
        'inspect', aliases=['insp', 'ins'], description=f'Inspect results: {__version__}', help='Inspect results'
    )
    # Sub-parser: inspect
    p_inspect_sub = p_inspect.add_subparsers(
        title='Inspect Commands', dest='subparsercmd', description='Inspect sub-commands', help='Inspect sub-commands'
    )

    ####### INSPECT: Copyleft ######
    # Inspect Sub-command: inspect copyleft
    p_copyleft = p_inspect_sub.add_parser(
        'copyleft', aliases=['cp'], description='Inspect for copyleft licenses', help='Inspect for copyleft licenses'
    )

    ####### INSPECT: License Summary ######
    # Inspect Sub-command: inspect license summary
    p_license_summary = p_inspect_sub.add_parser(
        'license-summary', aliases=['lic-summary', 'licsum'], description='Get license summary',
        help='Get detected license summary from scan results'
    )

    p_component_summary = p_inspect_sub.add_parser(
        'component-summary', aliases=['comp-summary', 'compsum'], description='Get component summary',
        help='Get detected component summary from scan results'
    )

    ####### INSPECT: Undeclared components ######
    # Inspect Sub-command: inspect undeclared
    p_undeclared = p_inspect_sub.add_parser(
        'undeclared',
        aliases=['un'],
        description='Inspect for undeclared components',
        help='Inspect for undeclared components',
    )
    p_undeclared.add_argument(
        '--sbom-format',
        required=False,
        choices=['legacy', 'settings'],
        default='settings',
        help='Sbom format for status output',
    )

    # Add common commands for inspect copyleft and license summary
    for p in [p_copyleft, p_license_summary]:
        p.add_argument(
            '--include',
            help='List of Copyleft licenses to append to the default list. Provide licenses as a comma-separated list.',
        )
        p.add_argument(
            '--exclude',
            help='List of Copyleft licenses to remove from default list. Provide licenses as a comma-separated list.',
        )
        p.add_argument(
            '--explicit',
            help='Explicit list of Copyleft licenses to consider. Provide licenses as a comma-separated list.s',
        )

        # Add common commands for inspect copyleft and license summary
    for p in [p_license_summary, p_component_summary]:
        p.add_argument('-i', '--input', nargs='?', help='Path to results file')
        p.add_argument('-o', '--output', type=str, help='Save summary into a file')

    p_undeclared.set_defaults(func=inspect_undeclared)
    p_copyleft.set_defaults(func=inspect_copyleft)
    p_license_summary.set_defaults(func=inspect_license_summary)
    p_component_summary.set_defaults(func=inspect_component_summary)

    ########################################### END INSPECT SUBCOMMAND ###########################################

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
    p_folder_hash.set_defaults(func=folder_hash)

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

    for p in [p_copyleft, p_undeclared]:
        p.add_argument('-i', '--input', nargs='?', help='Path to results file')
        p.add_argument(
            '-f',
            '--format',
            required=False,
            choices=['json', 'md', 'jira_md'],
            default='json',
            help='Output format (default: json)',
        )
        p.add_argument('-o', '--output', type=str, help='Save details into a file')
        p.add_argument('-s', '--status', type=str, help='Save summary data into Markdown file')

    # Global Scan command options
    for p in [p_scan, p_cs]:
        p.add_argument(
            '--apiurl', type=str, help='SCANOSS API URL (optional - default: https://api.osskb.org/scan/direct)'
        )
        p.add_argument('--ignore-cert-errors', action='store_true', help='Ignore certificate errors')

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
        p_undeclared,
        p_copyleft,
        p_license_summary,
        p_component_summary,
        c_provenance,
        p_folder_scan,
        p_folder_hash,
        p_cs,
        p_crypto_algorithms,
        p_crypto_hints,
        p_crypto_versions_in_range,
    ]:
        p.add_argument('--debug', '-d', action='store_true', help='Enable debug messages')
        p.add_argument('--trace', '-t', action='store_true', help='Enable trace messages, including API posts')
        p.add_argument('--quiet', '-q', action='store_true', help='Enable quiet mode')

    args = parser.parse_args()
    if args.version:
        ver(parser, args)
        sys.exit(0)
    if not args.subparser:
        parser.print_help()  # No sub command subcommand, print general help
        sys.exit(1)
    elif (
        args.subparser in ('utils', 'ut', 'component', 'comp', 'inspect', 'insp', 'ins', 'crypto', 'cr')
    ) and not args.subparsercmd:
        parser.parse_args([args.subparser, '--help'])  # Force utils helps to be displayed
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
    scan_output: str = None
    if args.output:
        scan_output = args.output
        open(scan_output, 'w').close()

    counter = FileCount(
        debug=args.debug,
        quiet=args.quiet,
        trace=args.trace,
        scan_output=scan_output,
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
    scan_output: str = None
    if args.output:
        scan_output = args.output
        open(scan_output, 'w').close()

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
    )
    if args.stdin:
        contents = sys.stdin.buffer.read()
        scanner.wfp_contents(args.stdin, contents, scan_output)
    elif args.scan_dir:
        if not os.path.exists(args.scan_dir):
            print_stderr(f'Error: File or folder specified does not exist: {args.scan_dir}.')
            sys.exit(1)
        if os.path.isdir(args.scan_dir):
            scanner.wfp_folder(args.scan_dir, scan_output)
        elif os.path.isfile(args.scan_dir):
            scanner.wfp_file(args.scan_dir, scan_output)
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
                scan_settings.load_json_file(args.settings, args.scan_dir).set_file_type('new').set_scan_type(
                    'identify'
                )
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

    scan_output: str = None
    if args.output:
        scan_output = args.output
        open(scan_output, 'w').close()
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

    if not os.access(os.getcwd(), os.W_OK):  # Make sure the current directory is writable. If not disable saving WFP
        print_stderr(f'Warning: Current directory is not writable: {os.getcwd()}')
        args.no_wfp_output = True
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
        scan_output=scan_output,
        output_format=output_format,
        flags=flags,
        nb_threads=args.threads,
        post_size=args.post_size,
        timeout=args.timeout,
        no_wfp_file=args.no_wfp_output,
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
    scan_output: str = None
    if args.output:
        scan_output = args.output
        open(scan_output, 'w').close()

    sc_deps = ScancodeDeps(
        debug=args.debug, quiet=args.quiet, trace=args.trace, sc_command=args.sc_command, timeout=args.sc_timeout
    )
    if not sc_deps.get_dependencies(what_to_scan=args.scan_loc, result_output=scan_output):
        sys.exit(1)


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
    else:
        print_stderr(f'ERROR: Unknown output format (--format): {args.format}')
    if not success:
        sys.exit(1)

################################ INSPECT handlers ################################
def inspect_copyleft(parser, args):
    """
    Run the "inspect" sub-command
    Parameters
    ----------
        parser: ArgumentParser
            command line parser object
        args: Namespace
            Parsed arguments
    """
    if args.input is None:
        print_stderr('Please specify an input file to inspect')
        parser.parse_args([args.subparser, args.subparsercmd, '-h'])
        sys.exit(1)
    output: str = None
    if args.output:
        output = args.output
        open(output, 'w').close()

    status_output: str = None
    if args.status:
        status_output = args.status
        open(status_output, 'w').close()

    i_copyleft = Copyleft(
        debug=args.debug,
        trace=args.trace,
        quiet=args.quiet,
        filepath=args.input,
        format_type=args.format,
        status=status_output,
        output=output,
        include=args.include,
        exclude=args.exclude,
        explicit=args.explicit,
    )
    status, _ = i_copyleft.run()
    sys.exit(status)


def inspect_undeclared(parser, args):
    """
    Run the "inspect" sub-command
    Parameters
    ----------
        parser: ArgumentParser
            command line parser object
        args: Namespace
            Parsed arguments
    """
    if args.input is None:
        print_stderr('Please specify an input file to inspect')
        parser.parse_args([args.subparser, args.subparsercmd, '-h'])
        sys.exit(1)
    output: str = None
    if args.output:
        output = args.output
        open(output, 'w').close()

    status_output: str = None
    if args.status:
        status_output = args.status
        open(status_output, 'w').close()
    i_undeclared = UndeclaredComponent(
        debug=args.debug,
        trace=args.trace,
        quiet=args.quiet,
        filepath=args.input,
        format_type=args.format,
        status=status_output,
        output=output,
        sbom_format=args.sbom_format,
    )
    status, _ = i_undeclared.run()
    sys.exit(status)

def inspect_license_summary(parser, args):
    """
       Run the "inspect" sub-command
       Parameters
       ----------
           parser: ArgumentParser
               command line parser object
           args: Namespace
               Parsed arguments
       """
    if args.input is None:
        print_stderr('Please specify an input file to inspect')
        parser.parse_args([args.subparser, args.subparsercmd, '-h'])
        sys.exit(1)
    output: str = None
    if args.output:
        output = args.output
        open(output, 'w').close()

    i_license_summary = LicenseSummary(
        debug=args.debug,
        trace=args.trace,
        quiet=args.quiet,
        filepath=args.input,
        output=output,
        include=args.include,
        exclude=args.exclude,
        explicit=args.explicit,
    )
    i_license_summary.run()

def inspect_component_summary(parser, args):
    """
       Run the "inspect" sub-command
       Parameters
       ----------
           parser: ArgumentParser
               command line parser object
           args: Namespace
               Parsed arguments
       """
    if args.input is None:
        print_stderr('Please specify an input file to inspect')
        parser.parse_args([args.subparser, args.subparsercmd, '-h'])
        sys.exit(1)
    output: str = None
    if args.output:
        output = args.output
        open(output, 'w').close()

    i_component_summary = ComponentSummary(
        debug=args.debug,
        trace=args.trace,
        quiet=args.quiet,
        filepath=args.input,
        output=output,
    )
    i_component_summary.run()

################################ End inspect handlers ################################

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
    )
    if not comps.get_provenance_details(args.input, args.purl, args.output, args.origin):
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


def main():
    """
    Run the ScanOSS CLI
    """
    setup_args()


if __name__ == '__main__':
    main()
