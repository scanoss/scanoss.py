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

import pypac

from .scanner import Scanner
from .scancodedeps import ScancodeDeps
from .scantype import ScanType
from .filecount import FileCount
from .cyclonedx import CycloneDx
from .spdxlite import SpdxLite
from .csvoutput import CsvOutput
from .components import Components
from . import __version__
from .scanner import FAST_WINNOWING


def print_stderr(*args, **kwargs):
    """
    Print the given message to STDERR
    """
    print(*args, file=sys.stderr, **kwargs)


def setup_args() -> None:
    """
    Setup all the command line arguments for processing
    """
    parser = argparse.ArgumentParser(description=f'SCANOSS Python CLI. Ver: {__version__}, License: MIT, Fast Winnowing: {FAST_WINNOWING}')
    parser.add_argument('--version', '-v', action='store_true', help='Display version details')

    subparsers = parser.add_subparsers(title='Sub Commands', dest='subparser', description='valid subcommands',
                                       help='sub-command help'
                                       )
    # Sub-command: version
    p_ver = subparsers.add_parser('version', aliases=['ver'],
                                  description=f'Version of SCANOSS CLI: {__version__}', help='SCANOSS version')
    p_ver.set_defaults(func=ver)

    # Sub-command: scan
    p_scan = subparsers.add_parser('scan', aliases=['sc'],
                                   description=f'Analyse/scan the given source base: {__version__}',
                                   help='Scan source code')
    p_scan.set_defaults(func=scan)
    p_scan.add_argument('scan_dir', metavar='FILE/DIR', type=str, nargs='?', help='A file or folder to scan')
    p_scan.add_argument('--wfp', '-w',  type=str,
                        help='Scan a WFP File instead of a folder (optional)'
                        )
    p_scan.add_argument('--dep', '-p',  type=str,
                        help='Use a dependency file instead of a folder (optional)'
                        )
    p_scan.add_argument('--stdin', '-s', metavar='STDIN-FILENAME',  type=str,
                        help='Scan the file contents supplied via STDIN (optional)'
                        )
    p_scan.add_argument('--identify', '-i', type=str, help='Scan and identify components in SBOM file')
    p_scan.add_argument('--ignore',   '-n', type=str, help='Ignore components specified in the SBOM file')
    p_scan.add_argument('--output',   '-o', type=str, help='Output result file name (optional - default stdout).')
    p_scan.add_argument('--format',   '-f', type=str, choices=['plain', 'cyclonedx', 'spdxlite', 'csv'],
                        help='Result output format (optional - default: plain)'
                        )
    p_scan.add_argument('--threads', '-T', type=int, default=10,
                        help='Number of threads to use while scanning (optional - default 10)'
                        )
    p_scan.add_argument('--flags', '-F', type=int,
                        help='Scanning engine flags (1: disable snippet matching, 2 enable snippet ids, '
                             '4: disable dependencies, 8: disable licenses, 16: disable copyrights,'
                             '32: disable vulnerabilities, 64: disable quality, 128: disable cryptography,'
                             '256: disable best match only, 512: hide identified files, '
                             '1024: enable download_url, 2048: enable GitHub full path, '
                             '4096: disable extended server stats)'
                        )
    p_scan.add_argument('--skip-snippets', '-S', action='store_true', help='Skip the generation of snippets')
    p_scan.add_argument('--post-size', '-P', type=int, default=64,
                        help='Number of kilobytes to limit the post to while scanning (optional - default 64)'
                        )
    p_scan.add_argument('--timeout', '-M', type=int, default=120,
                        help='Timeout (in seconds) for API communication (optional - default 120)'
                        )
    p_scan.add_argument('--no-wfp-output', action='store_true', help='Skip WFP file generation')
    p_scan.add_argument('--all-extensions', action='store_true', help='Scan all file extensions')
    p_scan.add_argument('--all-folders', action='store_true', help='Scan all folders')
    p_scan.add_argument('--all-hidden', action='store_true', help='Scan all hidden files/folders')
    p_scan.add_argument('--obfuscate', action='store_true', help='Obfuscate fingerprints')
    p_scan.add_argument('--dependencies', '-D', action='store_true', help='Add Dependency scanning')
    p_scan.add_argument('--dependencies-only', action='store_true', help='Run Dependency scanning only')
    p_scan.add_argument('--sc-command', type=str,
                        help='Scancode command and path if required (optional - default scancode).')
    p_scan.add_argument('--sc-timeout', type=int, default=600,
                        help='Timeout (in seconds) for scancode to complete (optional - default 600)'
                        )

    # Sub-command: fingerprint
    p_wfp = subparsers.add_parser('fingerprint', aliases=['fp', 'wfp'],
                                  description=f'Fingerprint the given source base: {__version__}',
                                  help='Fingerprint source code')
    p_wfp.set_defaults(func=wfp)
    p_wfp.add_argument('scan_dir', metavar='FILE/DIR', type=str, nargs='?',
                       help='A file or folder to scan')
    p_wfp.add_argument('--stdin', '-s', metavar='STDIN-FILENAME',  type=str,
                        help='Fingerprint the file contents supplied via STDIN (optional)'
                        )
    p_wfp.add_argument('--output', '-o', type=str, help='Output result file name (optional - default stdout).')
    p_wfp.add_argument('--obfuscate', action='store_true', help='Obfuscate fingerprints')
    p_wfp.add_argument('--skip-snippets', '-S', action='store_true', help='Skip the generation of snippets')
    p_wfp.add_argument('--all-extensions', action='store_true', help='Fingerprint all file extensions')
    p_wfp.add_argument('--all-folders', action='store_true', help='Fingerprint all folders')
    p_wfp.add_argument('--all-hidden', action='store_true', help='Fingerprint all hidden files/folders')

    # Sub-command: dependency
    p_dep = subparsers.add_parser('dependencies', aliases=['dp', 'dep'],
                                  description=f'Produce dependency file summary: {__version__}',
                                  help='Scan source code for dependencies, but do not decorate them')
    p_dep.set_defaults(func=dependency)
    p_dep.add_argument('scan_dir', metavar='FILE/DIR', type=str, nargs='?', help='A file or folder to scan')
    p_dep.add_argument('--output', '-o', type=str, help='Output result file name (optional - default stdout).')
    p_dep.add_argument('--sc-command', type=str,
                       help='Scancode command and path if required (optional - default scancode).')
    p_dep.add_argument('--sc-timeout', type=int, default=600,
                       help='Timeout (in seconds) for scancode to complete (optional - default 600)')

    # Sub-command: file_count
    p_fc = subparsers.add_parser('file_count', aliases=['fc'],
                                 description=f'Produce a file type count summary: {__version__}',
                                 help='Search the source tree and produce a file type summary')
    p_fc.set_defaults(func=file_count)
    p_fc.add_argument('scan_dir', metavar='DIR', type=str, nargs='?', help='A folder to search')
    p_fc.add_argument('--output', '-o', type=str, help='Output result file name (optional - default stdout).')
    p_fc.add_argument('--all-hidden', action='store_true', help='Scan all hidden files/folders')

    # Sub-command: convert
    p_cnv = subparsers.add_parser('convert', aliases=['cv', 'cnv', 'cvrt'],
                                  description=f'Convert results files between formats: {__version__}',
                                  help='Convert file format')
    p_cnv.set_defaults(func=convert)
    p_cnv.add_argument('--input', '-i', type=str, required=True, help='Input file name')
    p_cnv.add_argument('--output', '-o', type=str, help='Output result file name (optional - default stdout).')
    p_cnv.add_argument('--format', '-f', type=str, choices=['cyclonedx', 'spdxlite', 'csv'], default='spdxlite',
                       help='Output format (optional - default: spdxlite)')
    p_cnv.add_argument('--input-format', type=str, choices=['plain'], default='plain',
                       help='Input format (optional - default: plain)')

    # Sub-command: component
    p_comp = subparsers.add_parser('component', aliases=['comp'],
                                   description=f'SCANOSS Component commands: {__version__}',
                                   help='Component support commands')

    comp_sub = p_comp.add_subparsers(title='Component Commands', dest='subparsercmd', description='utils sub-commands',
                                     help='component sub-commands')

    # Component Sub-command: component crypto
    c_crypto = comp_sub.add_parser('crypto', aliases=['cr'],
                                   description=f'Show Cryptographic algorithms: {__version__}',
                                   help='Retreive the cryptographic algorithms for the given components')
    c_crypto.set_defaults(func=comp_crypto)

    c_crypto.add_argument('--purl',  '-p', type=str, nargs="*", help='Package URL - PURL to process.')
    c_crypto.add_argument('--input', '-i', type=str, help='Input file name')
    c_crypto.add_argument('--output','-o', type=str, help='Output result file name (optional - default stdout).')
    c_crypto.add_argument('--timeout', '-M', type=int, default=600,
                          help='Timeout (in seconds) for API communication (optional - default 600)')

    # Sub-command: utils
    p_util = subparsers.add_parser('utils', aliases=['ut'],
                                   description=f'SCANOSS Utility commands: {__version__}',
                                   help='General utility support commands')

    utils_sub = p_util.add_subparsers(title='Utils Commands', dest='subparsercmd', description='component sub-commands',
                                      help='component sub-commands')

    # Utils Sub-command: utils fast
    p_f_f = utils_sub.add_parser('fast',
                                  description=f'Is fast winnowing enabled: {__version__}', help='SCANOSS fast winnowing')
    p_f_f.set_defaults(func=fast)

    # Utils Sub-command: utils certloc
    p_c_loc = utils_sub.add_parser('certloc', aliases=['cl'],
                                   description=f'Show location of Python CA Certs: {__version__}',
                                   help='Display the location of Python CA Certs')
    p_c_loc.set_defaults(func=utils_certloc)

    # Utils Sub-command: utils cert-download
    p_c_dwnld = utils_sub.add_parser('cert-download', aliases=['cdl', 'cert-dl'],
                                     description=f'Download Server SSL Cert: {__version__}',
                                     help='Download the specified server\'s SSL PEM certificate')
    p_c_dwnld.set_defaults(func=utils_cert_download)
    p_c_dwnld.add_argument('--hostname', '-n', required=True, type=str, help='Server hostname to download cert from.')
    p_c_dwnld.add_argument('--port', '-p', required=False, type=int, default=443,
                           help='Server port number (default: 443).')
    p_c_dwnld.add_argument('--output', '-o', type=str, help='Output result file name (optional - default stdout).')

    # Utils Sub-command: utils pac-proxy
    p_p_proxy = utils_sub.add_parser('pac-proxy', aliases=['pac'],
                                     description=f'Determine Proxy from PAC: {__version__}',
                                     help='Use Proxy Auto-Config to determine proxy configuration')
    p_p_proxy.set_defaults(func=utils_pac_proxy)
    p_p_proxy.add_argument('--pac', required=False, type=str, default="auto",
                           help='Proxy auto configuration. Specify a file, http url or "auto" to try to discover it.'
                           )
    p_p_proxy.add_argument('--url', required=False, type=str, default="https://osskb.org/api",
                           help='URL to test (default: https://osskb.org/api).')

    # Global Scan command options
    for p in [p_scan]:
        p.add_argument('--apiurl', type=str,
                       help='SCANOSS API URL (optional - default: https://osskb.org/api/scan/direct)'
                       )
        p.add_argument('--ignore-cert-errors', action='store_true', help='Ignore certificate errors')

    # Global Scan/GRPC options
    for p in [p_scan, c_crypto]:
        p.add_argument('--key', '-k', type=str,
                       help='SCANOSS API Key token (optional - not required for default OSSKB URL)'
                       )
        p.add_argument('--proxy', type=str, help='Proxy URL to use for connections (optional). '
                                                 'Can also use the environment variable "HTTPS_PROXY=<ip>:<port>" '
                                                 'and "grcp_proxy=<ip>:<port>" for gRPC'
                       )
        p.add_argument('--pac', type=str, help='Proxy auto configuration (optional). '
                                               'Specify a file, http url or "auto" to try to discover it.'
                       )
        p.add_argument('--ca-cert', type=str, help='Alternative certificate PEM file (optional). '
                                                   'Can also use the environment variable '
                                                   '"REQUESTS_CA_BUNDLE=/path/to/cacert.pem" and '
                                                   '"GRPC_DEFAULT_SSL_ROOTS_FILE_PATH=/path/to/cacert.pem" for gRPC'
                       )

    # Global GRPC options
    for p in [p_scan, c_crypto]:
        p.add_argument('--api2url', type=str,
                       help='SCANOSS gRPC API 2.0 URL (optional - default: https://api.osskb.org)'
                       )
        p.add_argument('--grpc-proxy', type=str, help='GRPC Proxy URL to use for connections (optional). '
                                                       'Can also use the environment variable "grcp_proxy=<ip>:<port>"'
                       )

    # Help/Trace command options
    for p in [p_scan, p_wfp, p_dep, p_fc, p_cnv, p_c_loc, p_c_dwnld, p_p_proxy, c_crypto]:
        p.add_argument('--debug', '-d', action='store_true', help='Enable debug messages')
        p.add_argument('--trace', '-t', action='store_true', help='Enable trace messages, including API posts')
        p.add_argument('--quiet', '-q', action='store_true', help='Enable quiet mode')

    args = parser.parse_args()
    if args.version:
        ver(parser, args)
        exit(0)
    if not args.subparser:
        parser.print_help()  # No sub command subcommand, print general help
        exit(1)
    else:
        if (args.subparser == 'utils' or args.subparser == 'ut' or
            args.subparser == 'component' or args.subparser == 'comp') \
                and not args.subparsercmd:
            parser.parse_args([args.subparser, '--help'])  # Force utils helps to be displayed
            exit(1)
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
        exit(1)
    scan_output: str = None
    if args.output:
        scan_output = args.output
        open(scan_output, 'w').close()

    counter = FileCount(debug=args.debug, quiet=args.quiet, trace=args.trace, scan_output=scan_output,
                        hidden_files_folders=args.all_hidden
                        )
    if not os.path.exists(args.scan_dir):
        print_stderr(f'Error: Folder specified does not exist: {args.scan_dir}.')
        exit(1)
    if os.path.isdir(args.scan_dir):
        counter.count_files(args.scan_dir)
    else:
        print_stderr(f'Error: Path specified is not a folder: {args.scan_dir}.')
        exit(1)


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
        exit(1)
    scan_output: str = None
    if args.output:
        scan_output = args.output
        open(scan_output, 'w').close()

    scan_options = 0 if args.skip_snippets else ScanType.SCAN_SNIPPETS.value  # Skip snippet generation or not
    scanner = Scanner(debug=args.debug, trace=args.trace, quiet=args.quiet, obfuscate=args.obfuscate,
                      scan_options=scan_options, all_extensions=args.all_extensions,
                      all_folders=args.all_folders, hidden_files_folders=args.all_hidden)

    if args.stdin:
        contents = sys.stdin.buffer.read()
        scanner.wfp_contents(args.stdin, contents, scan_output)
    elif args.scan_dir:
        if not os.path.exists(args.scan_dir):
            print_stderr(f'Error: File or folder specified does not exist: {args.scan_dir}.')
            exit(1)
        if os.path.isdir(args.scan_dir):
            scanner.wfp_folder(args.scan_dir, scan_output)
        elif os.path.isfile(args.scan_dir):
            scanner.wfp_file(args.scan_dir, scan_output)
        else:
            print_stderr(f'Error: Path specified is neither a file or a folder: {args.scan_dir}.')
            exit(1)
    else:
        print_stderr('No action found to process')
        exit(1)


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
    if args.dependencies:
        scan_dependencies = ScanType.SCAN_DEPENDENCIES.value
    if args.dependencies_only:
        scan_files = scan_snippets = 0
        scan_dependencies = ScanType.SCAN_DEPENDENCIES.value

    scan_options = scan_files + scan_snippets + scan_dependencies

    if args.debug:
        if ScanType.SCAN_FILES.value & scan_options:
            print_stderr(f'Scan Files')
        if ScanType.SCAN_SNIPPETS.value & scan_options:
            print_stderr(f'Scan Snippets')
        if ScanType.SCAN_DEPENDENCIES.value & scan_options:
            print_stderr(f'Scan Dependencies')
    if scan_options <= 0:
        print_stderr(f'Error: No valid scan options configured: {scan_options}')
        exit(1)
    return scan_options


def scan(parser, args):
    """
    Run the "scan" sub-command
    Parameters
    ----------
        parser: ArgumentParser
            command line parser object
        args: Namespace
            Parsed arguments
    """
    if not args.scan_dir and not args.wfp and not args.stdin:
        print_stderr('Please specify a file/folder, fingerprint (--wfp) or STDIN (--stdin)')
        parser.parse_args([args.subparser, '-h'])
        exit(1)
    if args.pac and args.proxy:
        print_stderr('Please specify one of --proxy or --pac, not both')
        parser.parse_args([args.subparser, '-h'])
        exit(1)
    scan_type: str = None
    sbom_path: str = None
    if args.identify:
        sbom_path = args.identify
        scan_type = 'identify'
        if not os.path.exists(sbom_path) or not os.path.isfile(sbom_path):
            print_stderr(f'Specified --identify file does not exist or is not a file: {sbom_path}')
            exit(1)
        if not Scanner.valid_json_file(sbom_path):   # Make sure it's a valid JSON file
            exit(1)
        if args.ignore:
            print_stderr(f'Warning: Specified --identify and --ignore options. Skipping ignore.')
    elif args.ignore:
        sbom_path = args.ignore
        scan_type = 'blacklist'
        if not os.path.exists(sbom_path) or not os.path.isfile(sbom_path):
            print_stderr(f'Specified --ignore file does not exist or is not a file: {sbom_path}')
            exit(1)
        if not Scanner.valid_json_file(sbom_path):   # Make sure it's a valid JSON file
            exit(1)
    if args.dep:
        if not os.path.exists(args.dep) or not os.path.isfile(args.dep):
            print_stderr(f'Specified --dep file does not exist or is not a file: {args.dep}')
            exit(1)
        if not Scanner.valid_json_file(args.dep):  # Make sure it's a valid JSON file
            exit(1)

    scan_output: str = None
    if args.output:
        scan_output = args.output
        open(scan_output, 'w').close()
    output_format = args.format if args.format else 'plain'
    flags = args.flags if args.flags else None
    if args.debug and not args.quiet:
        if args.all_extensions:
            print_stderr("Scanning all file extensions/types...")
        if args.all_folders:
            print_stderr("Scanning all folders...")
        if args.all_hidden:
            print_stderr("Scanning all hidden files/folders...")
        if args.skip_snippets:
            print_stderr("Skipping snippets...")
        if args.post_size != 64:
            print_stderr(f'Changing scanning POST size to: {args.post_size}k...')
        if args.timeout != 120:
            print_stderr(f'Changing scanning POST timeout to: {args.timeout}...')
        if args.obfuscate:
            print_stderr("Obfuscating file fingerprints...")
        if args.proxy:
            print_stderr(f'Using Proxy {args.proxy}...')
        if args.grpc_proxy:
            print_stderr(f'Using GRPC Proxy {args.grpc_proxy}...')
        if args.pac:
            print_stderr(f'Using Proxy Auto-config (PAC) {args.pac}...')
        if args.ca_cert:
            print_stderr(f'Using Certificate {args.ca_cert}...')
        if flags:
            print_stderr(f'Using flags {flags}...')
    elif not args.quiet:
        if args.timeout < 5:
            print_stderr(f'POST timeout (--timeout) too small: {args.timeout}. Reverting to default.')

    if not os.access(os.getcwd(), os.W_OK):  # Make sure the current directory is writable. If not disable saving WFP
        print_stderr(f'Warning: Current directory is not writable: {os.getcwd()}')
        args.no_wfp_output = True
    if args.ca_cert and not os.path.exists(args.ca_cert):
        print_stderr(f'Error: Certificate file does not exist: {args.ca_cert}.')
        exit(1)
    pac_file = get_pac_file(args.pac)
    scan_options = get_scan_options(args)   # Figure out what scanning options we have

    scanner = Scanner(debug=args.debug, trace=args.trace, quiet=args.quiet, api_key=args.key, url=args.apiurl,
                      sbom_path=sbom_path, scan_type=scan_type, scan_output=scan_output, output_format=output_format,
                      flags=flags, nb_threads=args.threads, post_size=args.post_size,
                      timeout=args.timeout, no_wfp_file=args.no_wfp_output, all_extensions=args.all_extensions,
                      all_folders=args.all_folders, hidden_files_folders=args.all_hidden,
                      scan_options=scan_options, sc_timeout=args.sc_timeout, sc_command=args.sc_command,
                      grpc_url=args.api2url, obfuscate=args.obfuscate,
                      ignore_cert_errors=args.ignore_cert_errors, proxy=args.proxy, grpc_proxy=args.grpc_proxy,
                      pac=pac_file, ca_cert=args.ca_cert
                      )
    if args.wfp:
        if not scanner.is_file_or_snippet_scan():
            print_stderr(f'Error: Cannot specify WFP scanning if file/snippet options are disabled ({scan_options})')
            exit(1)
        if args.threads > 1:
            scanner.scan_wfp_file_threaded(args.wfp)
        else:
            scanner.scan_wfp_file(args.wfp)
    elif args.stdin:
        contents = sys.stdin.buffer.read()
        if not scanner.scan_contents(args.stdin, contents):
            exit(1)
    elif args.scan_dir:
        if not os.path.exists(args.scan_dir):
            print_stderr(f'Error: File or folder specified does not exist: {args.scan_dir}.')
            exit(1)
        if os.path.isdir(args.scan_dir):
            if not scanner.scan_folder_with_options(args.scan_dir, scanner.winnowing.file_map):
                exit(1)
        elif os.path.isfile(args.scan_dir):
            if not scanner.scan_file_with_options(args.scan_dir, scanner.winnowing.file_map):
                exit(1)
        else:
            print_stderr(f'Error: Path specified is neither a file or a folder: {args.scan_dir}.')
            exit(1)
    else:
        print_stderr('No action found to process')
        exit(1)


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
    if not args.scan_dir:
        print_stderr('Please specify a file/folder')
        parser.parse_args([args.subparser, '-h'])
        exit(1)
    if not os.path.exists(args.scan_dir):
        print_stderr(f'Error: File or folder specified does not exist: {args.scan_dir}.')
        exit(1)
    scan_output: str = None
    if args.output:
        scan_output = args.output
        open(scan_output, 'w').close()

    sc_deps = ScancodeDeps(debug=args.debug, quiet=args.quiet, trace=args.trace, sc_command=args.sc_command,
                           timeout=args.sc_timeout
                           )
    if not sc_deps.get_dependencies(what_to_scan=args.scan_dir, result_output=scan_output):
        exit(1)


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
        exit(1)
    success = False
    if args.format == 'cyclonedx':
        if not args.quiet:
            print_stderr(f'Producing CycloneDX report...')
        cdx = CycloneDx(debug=args.debug, output_file=args.output)
        success = cdx.produce_from_file(args.input)
    elif args.format == 'spdxlite':
        if not args.quiet:
            print_stderr(f'Producing SPDX Lite report...')
        spdxlite = SpdxLite(debug=args.debug, output_file=args.output)
        success = spdxlite.produce_from_file(args.input)
    elif args.format == 'csv':
        if not args.quiet:
            print_stderr(f'Producing CSV report...')
        csvo = CsvOutput(debug=args.debug, output_file=args.output)
        success = csvo.produce_from_file(args.input)
    else:
        print_stderr(f'ERROR: Unknown output format (--format): {args.format}')
    if not success:
        exit(1)


def utils_certloc(*_):
    """
    Run the "utils certloc" sub-command
    :param _: ignored/unused
    """
    import certifi
    print(f'CA Cert File: {certifi.where()}')


def utils_cert_download(_, args):
    """
    Run the "utils cert-download" sub-command
    :param _: ignore/unused
    :param args: Parsed arguments
    """
    from urllib.parse import urlparse
    import socket
    from OpenSSL import SSL, crypto
    import traceback

    file = sys.stdout
    hostname = 'unset'
    port = 'unkown'
    if args.output:
        file = open(args.output, 'w')
    parsed_url = urlparse(args.hostname)
    hostname = parsed_url.hostname or args.hostname  # Use the parse hostname, or it None use the supplied one
    port = int(parsed_url.port or args.port)  # Use the parsed port, if not use the supplied one (default 443)
    certs = []
    try:
        if args.debug:
            print_stderr(f'Connecting to {hostname} on {port}...')
        conn = SSL.Connection(SSL.Context(SSL.TLSv1_2_METHOD), socket.socket())
        conn.connect((hostname, port))
        conn.do_handshake()
        certs = conn.get_peer_cert_chain()
        for index, cert in enumerate(certs):
            cert_components = dict(cert.get_subject().get_components())
            if(sys.version_info[0] >= 3):
                cn = cert_components.get(b'CN')
            else:
                cn = cert_components.get('CN')
            if not args.quiet:
                print_stderr(f'Centificate {index} - CN: {cn}')
            if(sys.version_info[0] >= 3):
                print((crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode('utf-8')).strip(), file=file)  # Print the downloaded PEM certificate
            else:
                print((crypto.dump_certificate(crypto.FILETYPE_PEM, cert)).strip(), file=file)
    except SSL.Error as e:
        print_stderr(f'ERROR: Exception ({e.__class__.__name__}) Downloading certificate from {hostname}:{port} - {e}.')
        if args.debug:
            traceback.print_exc()
        exit(1)
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
    from pypac.resolver import ProxyResolver
    if not args.pac:
        print_stderr(f'Error: No pac file option specified.')
        exit(1)
    pac_file = get_pac_file(args.pac)
    if pac_file is None:
        print_stderr(f'No proxy configuration for: {args.pac}')
        exit(1)
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
            pac_local = pac.strip('file://')
            if not os.path.exists(pac_local):
                print_stderr(f'Error: PAC file does not exist: {pac_local}.')
                exit(1)
            with open(pac_local) as pf:
                pac_file = pypac.get_pac(js=pf.read())
        elif pac.startswith('http'):
            pac_file = pypac.get_pac(url=pac)
        else:
            print_stderr(f'Error: Unknown PAC file option: {pac}. Should be one of "auto", "file://", "https://"')
            exit(1)
    return pac_file


def comp_crypto(parser, args):
    """
    Run the "component crypto" sub-command
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
        exit(1)
    if args.ca_cert and not os.path.exists(args.ca_cert):
        print_stderr(f'Error: Certificate file does not exist: {args.ca_cert}.')
        exit(1)
    pac_file = get_pac_file(args.pac)
    comps = Components(debug=args.debug, trace=args.trace, quiet=args.quiet, grpc_url=args.api2url, api_key=args.key,
                           ca_cert=args.ca_cert, proxy=args.proxy, grpc_proxy=args.grpc_proxy, pac=pac_file,
                       timeout=args.timeout)
    if not comps.get_crypto_details(args.input, args.purl, args.output):
        exit(1)
def main():
    """
    Run the ScanOSS CLI
    """
    setup_args()


if __name__ == "__main__":
    main()
