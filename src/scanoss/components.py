"""
 SPDX-License-Identifier: MIT

   Copyright (c) 2023, SCANOSS

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
import json
import os
import sys
from typing import TextIO

from pypac.parser import PACFile

from .scanner import Scanner
from .scanossbase import ScanossBase
from .scanossgrpc import ScanossGrpc


class Components(ScanossBase):
    """
    Class for Component functionality
    """

    def __init__(self, debug: bool = False, trace: bool = False, quiet: bool = False,
                 grpc_url: str = None, api_key: str = None, timeout: int = 600,
                 proxy: str = None, grpc_proxy: str = None, ca_cert: str = None, pac: PACFile = None
                 ):
        """
        Handle all component style requests

        :param debug: Debug
        :param trace: Trace
        :param quiet: Quiet
        :param grpc_url: gRPC URL
        :param api_key: API Key
        :param timeout: Timeout for requests (default 600)
        :param proxy: Proxy to use (optional)
        :param grpc_proxy: Specific gRPC proxy (optional)
        :param ca_cert: TLS client certificate (optional)
        :param pac: Proxy Auto-Config file (optional)
        """
        super().__init__(debug, trace, quiet)
        ver_details = Scanner.version_details()
        self.grpc_api = ScanossGrpc(url=grpc_url, debug=debug, quiet=quiet, trace=trace, api_key=api_key,
                                    ver_details=ver_details, ca_cert=ca_cert, proxy=proxy, pac=pac,
                                    grpc_proxy=grpc_proxy, timeout=timeout)

    def load_purls(self, json_file: str = None, purls: [] = None) -> dict:
        """
        Load the specified purls and return a dictionary

        :param json_file: JSON PURL file (optional)
        :param purls: list of PURLs (optional)
        :return: PURL Request dictionary
        """
        if json_file:
            if not os.path.isfile(json_file) or not os.access(json_file, os.R_OK):
                self.print_stderr(f'ERROR: JSON file does not exist, is not a file, or is not readable: {json_file}')
                return None
            with open(json_file, 'r') as f:
                try:
                    purl_request = json.loads(f.read())
                except Exception as e:
                    self.print_stderr(f'ERROR: Problem parsing input JSON: {e}')
                    return None
        elif purls:
            parsed_purls = []
            for p in purls:
                parsed_purls.append({'purl': p})
            purl_request = {'purls': parsed_purls}
        else:
            self.print_stderr('ERROR: No purls specified to process.')
            return None
        purl_count = len(purl_request.get('purls', []))
        self.print_debug(f'Parsed Purls ({purl_count}): {purl_request}')
        if purl_count == 0:
            self.print_stderr('ERROR: No PURLs parsed from request.')
            return None
        return purl_request

    def _open_file_or_sdtout(self, filename):
        """
        Open the given filename if requested, otherwise return STDOUT

        :param filename:
        :return:
        """
        file = sys.stdout
        if filename:
            try:
                file = open(filename, 'w')
            except OSError as e:
                self.print_stderr(f'ERROR: Failed to open output file {filename}: {e}')
                return None
        return file

    def _close_file(self, filename: str = None, file: TextIO = None) -> None:
        """
        Close the file descriptor if its defined

        :param filename: filename
        :param file: file IO object
        :return: None
        """
        if filename and file:
            self.print_trace(f'Closing file: {filename}')
            file.close()

    def get_crypto_details(self, json_file: str = None, purls: [] = None, output_file: str = None) -> bool:
        """
        Retrieve the cryptographic details for the supplied PURLs

        :param json_file: PURL JSON request file (optional)
        :param purls: PURL request array (optional)
        :param output_file: output filename (optional). Default: STDOUT
        :return: True on success, False otherwise
        """
        success = False
        purls_request = self.load_purls(json_file, purls)
        if purls_request is None or len(purls_request) == 0:
            return False
        file = self._open_file_or_sdtout(output_file)
        if file is None:
            return False
        self.print_msg('Sending PURLs to Crypto API for decoration...')
        response = self.grpc_api.get_crypto_json(purls_request)
        if response:
            print(json.dumps(response, indent=2, sort_keys=True), file=file)
            success = True
            if output_file:
                self.print_msg(f'Results written to: {output_file}')
        self._close_file(output_file, file)
        return success
