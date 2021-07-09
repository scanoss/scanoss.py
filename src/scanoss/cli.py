#!/usr/bin/env python3
"""
 SPDX-License-Identifier: GPL-2.0-or-later

   Copyright (C) 2018-2021 SCANOSS LTD

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import argparse
import os
import sys

from .scanner import Scanner
from .winnowing import Winnowing
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
    parser = argparse.ArgumentParser(description=f'SCANOSS Python CLI. Ver: {__version__}, License: GPL 2.0-or-later')
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
    p_scan.add_argument('--identify', '-i', type=str, help='Scan and identify components in SBOM file' )
    p_scan.add_argument('--ignore', '-n', type=str, help='Ignore components specified in the SBOM file' )
    p_scan.add_argument('--output', '-o', type=str, help='Output result file name (optional - default stdout).' )
    p_scan.add_argument('--format', '-f', type=str, choices=['plain', 'cyclonedx'],
                        help='Result output format (optional - default: plain)'
                        )
    p_scan.add_argument('--flags', '-F', type=int,
                        help='Scanning engine flags (1: disable snippet matching, 2 enable snippet ids, '
                             '4: disable dependencies, 8: disable licenses, 16: disable copyrights,'
                             '32: disable vulnerabilities, 64: disable quality, 128: disable cryptography,'
                             '256: disable best match, 512: Report identified files)'
                        )
    # Sub-command: fingerprint
    p_wfp = subparsers.add_parser('fingerprint', aliases=['fp', 'wfp'],
                                  description=f'Fingerprint the given source base: {__version__}',
                                  help='Fingerprint source code')
    p_wfp.set_defaults(func=wfp)
    p_wfp.add_argument('scan_dir', metavar='FILE/DIR', type=str, nargs='?',
                       help='A file or folder to scan')
    p_wfp.add_argument('--output', '-o', type=str, help='Output result file name (optional - default stdout).' )

    # Global command options
    for p in [p_scan]:
        p.add_argument('--key', '-k', type=str,
                       help='SCANOSS API Key token (optional - not required for default OSSKB URL)'
                       )
        p.add_argument('--apiurl', type=str,
                       help='SCANOSS API URL (optional - default: https://osskb.org/api/scan/direct)'
                       )
    for p in [p_scan, p_wfp]:
        p.add_argument('--debug', '-d', action='store_true', help='Enable debug messages')
        p.add_argument('--trace', '-t', action='store_true', help='Enable trace messages, including API posts')
        p.add_argument('--quiet', '-q', action='store_true', help='Enable quiet mode')

    args = parser.parse_args()
    if not args.subparser:
        parser.print_help()
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
    scanner = Scanner(debug=args.debug, quiet=args.quiet)

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

    scan_output: str = None
    if args.output:
        scan_output = args.output
        open(scan_output, 'w').close()
    output_format = args.format if args.format else 'plain'
    flags = args.flags if args.flags else None
    scanner = Scanner(debug=args.debug, trace=args.trace, quiet=args.quiet, api_key=args.key, url=args.apiurl,
                      sbom_path=sbom_path, scan_type=scan_type, scan_output=scan_output, output_format=output_format,
                      flags=flags
                      )
    if args.wfp:
        scanner.scan_wfp_file(args.wfp)
    elif args.scan_dir:
        if not os.path.exists(args.scan_dir):
            print_stderr(f'Error: File or folder specified does not exist: {args.scan_dir}.')
            exit(1)
        if os.path.isdir(args.scan_dir):
            scanner.scan_folder(args.scan_dir)
        elif os.path.isfile(args.scan_dir):
            scanner.scan_file(args.scan_dir)
        else:
            print_stderr(f'Error: Path specified is neither a file or a folder: {args.scan_dir}.')
            exit(1)
    else:
        print_stderr('No action found to process')
        exit(1)


def main():
    """
    Run the ScanOSS CLI
    """
    setup_args()


if __name__ == "__main__":
    main()
