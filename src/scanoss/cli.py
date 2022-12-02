#!/usr/bin/env python3
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

from .scanner import Scanner
from .winnowing import Winnowing
from .scancodedeps import ScancodeDeps
from .scantype import ScanType
from .filecount import FileCount
from .cyclonedx import CycloneDx
from .spdxlite import SpdxLite
from .csvoutput import CsvOutput
from . import __version__


def print_stderr(*args, **kwargs):
    """
    Print the given message to STDERR
    """
    print(*args, file=sys.stderr, **kwargs)


def setup_args() -> None:
    """
    Setup all the command line arguments for processing
    """
    parser = argparse.ArgumentParser(description=f'SCANOSS Python CLI. Ver: {__version__}, License: MIT')
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
    p_scan.add_argument('--identify', '-i', type=str, help='Scan and identify components in SBOM file' )
    p_scan.add_argument('--ignore',   '-n', type=str, help='Ignore components specified in the SBOM file' )
    p_scan.add_argument('--output',   '-o', type=str, help='Output result file name (optional - default stdout).' )
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
                             '256: disable best match, 512: Report identified files)'
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
    p_scan.add_argument('--sc-command', type=str, help='Scancode command and path if required (optional - default scancode).' )
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
    p_wfp.add_argument('--output', '-o', type=str, help='Output result file name (optional - default stdout).' )
    p_wfp.add_argument('--obfuscate', action='store_true', help='Obfuscate fingerprints')
    p_wfp.add_argument('--skip-snippets', '-S', action='store_true', help='Skip the generation of snippets')

    # Sub-command: dependency
    p_dep = subparsers.add_parser('dependencies', aliases=['dp', 'dep'],
                                  description=f'Produce dependency file summary: {__version__}',
                                  help='Scan source code for dependencies, but do not decorate them')
    p_dep.set_defaults(func=dependency)
    p_dep.add_argument('scan_dir', metavar='FILE/DIR', type=str, nargs='?', help='A file or folder to scan')
    p_dep.add_argument('--output', '-o', type=str, help='Output result file name (optional - default stdout).' )
    p_dep.add_argument('--sc-command', type=str, help='Scancode command and path if required (optional - default scancode).' )
    p_dep.add_argument('--sc-timeout', type=int, default=600,
                        help='Timeout (in seconds) for scancode to complete (optional - default 600)'
                        )

    # Sub-command: file_count
    p_fc = subparsers.add_parser('file_count', aliases=['fc'],
                                 description=f'Produce a file type count summary: {__version__}',
                                 help='Search the source tree and produce a file type summary')
    p_fc.set_defaults(func=file_count)
    p_fc.add_argument('scan_dir', metavar='DIR', type=str, nargs='?', help='A folder to search')
    p_fc.add_argument('--output', '-o', type=str, help='Output result file name (optional - default stdout).' )
    p_fc.add_argument('--all-hidden', action='store_true', help='Scan all hidden files/folders')

    # Sub-command: convert
    p_cnv = subparsers.add_parser('convert', aliases=['cv', 'cnv', 'cvrt'],
                                   description=f'Convert results files between formats: {__version__}',
                                   help='Convert file format')
    p_cnv.set_defaults(func=convert)
    p_cnv.add_argument('--input', '-i', type=str, required=True, help='Input file name')
    p_cnv.add_argument('--output','-o', type=str, help='Output result file name (optional - default stdout).' )
    p_cnv.add_argument('--format','-f', type=str, choices=['cyclonedx', 'spdxlite', 'csv'], default='spdxlite',
                       help='Output format (optional - default: spdxlite)'
                       )
    p_cnv.add_argument('--input-format', type=str, choices=['plain'], default='plain',
                       help='Input format (optional - default: plain)'
                       )

    # Sub-command: utils
    p_util = subparsers.add_parser('utils', aliases=['ut', 'util'],
                                   description=f'SCANOSS Utility commands: {__version__}',
                                   help='General utility support commands')

    utils_sub = p_util.add_subparsers(title='Utils Commands', dest='utilsubparser', description='utils sub-commands',
                                       help='utils sub-commands'
                                       )

    # Utils Sub-command: utils certloc
    p_c_loc = utils_sub.add_parser('certloc', aliases=['cl'],
                                   description=f'Show location of Python CA Certs: {__version__}',
                                   help='Display the location of Python CA Certs')
    p_c_loc.set_defaults(func=utils_certloc)

    # Global command options
    for p in [p_scan]:
        p.add_argument('--key', '-k', type=str,
                       help='SCANOSS API Key token (optional - not required for default OSSKB URL)'
                       )
        p.add_argument('--apiurl', type=str,
                       help='SCANOSS API URL (optional - default: https://osskb.org/api/scan/direct)'
                       )
        p.add_argument('--api2url', type=str,
                       help='SCANOSS gRPC API 2.0 URL (optional - default: https://api.osskb.org)'
                       )
        p.add_argument('--proxy', type=str, help='Proxy URL to use for connections (optional). '
                                                 'Can also use the environment variable "HTTPS_PROXY=<ip>:<port>" '
                                                 'and "grcp_proxy=<ip>:<port>" for gRPC'
                       )
        p.add_argument('--ca-cert', type=str, help='Alternative certificate PEM file (optional). '
                                                   'Can also use the environment variable '
                                                   '"REQUESTS_CA_BUNDLE=/path/to/cacert.pem" and '
                                                   '"GRPC_DEFAULT_SSL_ROOTS_FILE_PATH=/path/to/cacert.pem" for gRPC'
                       )
        p.add_argument('--ignore-cert-errors', action='store_true', help='Ignore certificate errors')

    for p in [p_scan, p_wfp, p_dep, p_fc, p_cnv, p_c_loc]:
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
    elif args.subparser == 'utils' and not args.utilsubparser:  # No utils sub command supplied
        parser.parse_args([args.subparser, '--help'])  # Force utils helps to be displayed
        exit(1)
    args.func(parser, args)  # Execute the function associated with the sub-command


def ver(parser, args):
    """
    Run the "ver" sub-command
    Parameters
    ----------
        parser: ArgumentParser
            command line parser object
        args: Namespace
            Parsed arguments
    """
    print(f'Version: {__version__}')

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
    if not args.scan_dir:
        print_stderr('Please specify a file/folder')
        parser.parse_args([args.subparser, '-h'])
        exit(1)
    scan_output: str = None
    if args.output:
        scan_output = args.output
        open(scan_output, 'w').close()

    scan_options = 0 if args.skip_snippets else ScanType.SCAN_SNIPPETS.value  # Skip snippet generation or not
    scanner = Scanner(debug=args.debug, quiet=args.quiet, obfuscate=args.obfuscate, scan_options=scan_options)

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
    if not args.scan_dir and not args.wfp:
        print_stderr('Please specify a file/folder or fingerprint (--wfp)')
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
            print_stderr(f'Using Proxy {arg.proxy}...')
        if args.ca_cert:
            print_stderr(f'Using Certificate {arg.ca_cert}...')
    elif not args.quiet:
        if args.timeout < 5:
            print_stderr(f'POST timeout (--timeout) too small: {args.timeout}. Reverting to default.')

    if not os.access( os.getcwd(), os.W_OK ):  # Make sure the current directory is writable. If not disable saving WFP
        print_stderr(f'Warning: Current directory is not writable: {os.getcwd()}')
        args.no_wfp_output = True
    if args.ca_cert and not os.path.exists(args.ca_cert):
        print_stderr(f'Error: Certificate file does not exist: {args.ca_cert}.')
        exit(1)
    scan_options = get_scan_options(args)   # Figure out what scanning options we have

    scanner = Scanner(debug=args.debug, trace=args.trace, quiet=args.quiet, api_key=args.key, url=args.apiurl,
                      sbom_path=sbom_path, scan_type=scan_type, scan_output=scan_output, output_format=output_format,
                      flags=flags, nb_threads=args.threads, post_size=args.post_size,
                      timeout=args.timeout, no_wfp_file=args.no_wfp_output, all_extensions=args.all_extensions,
                      all_folders=args.all_folders, hidden_files_folders=args.all_hidden,
                      scan_options=scan_options, sc_timeout=args.sc_timeout, sc_command=args.sc_command,
                      grpc_url=args.api2url, obfuscate=args.obfuscate,
                      ignore_cert_errors=args.ignore_cert_errors, proxy=args.proxy, ca_cert=args.ca_cert
                      )
    if args.wfp:
        if not scanner.is_file_or_snippet_scan():
            print_stderr(f'Error: Cannot specify WFP scanning if file/snippet options are disabled ({scan_options})')
            exit(1)
        if args.threads > 1:
            scanner.scan_wfp_file_threaded(args.wfp)
        else:
            scanner.scan_wfp_file(args.wfp)
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

def utils_certloc(parser, args):
    """
    Run the "utils certloc" sub-command
    Parameters
    ----------
        parser: ArgumentParser
            command line parser object
        args: Namespace
            Parsed arguments
    """
    import certifi
    print(f'CA Cert File: {certifi.where()}')

def main():
    """
    Run the ScanOSS CLI
    """
    setup_args()


if __name__ == "__main__":
    main()
