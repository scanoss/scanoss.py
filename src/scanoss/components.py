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
from typing import List, Optional, TextIO

from pypac.parser import PACFile

from scanoss.cyclonedx import CycloneDx
from scanoss.utils.file import validate_json_file

from .scanner import Scanner
from .scanossbase import ScanossBase
from .scanossgrpc import ScanossGrpc


class Components(ScanossBase):
    """
    Class for Component functionality
    """

    def __init__(  # noqa: PLR0913, PLR0915
        self,
        debug: bool = False,
        trace: bool = False,
        quiet: bool = False,
        grpc_url: str = None,
        api_key: str = None,
        timeout: int = 600,
        proxy: str = None,
        grpc_proxy: str = None,
        ca_cert: str = None,
        pac: PACFile = None,
        req_headers: dict = None,
        ignore_cert_errors: bool = False,
        use_grpc: bool = False,
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
        :param req_headers: Additional headers to send with requests (optional)
        :param ignore_cert_errors: Ignore TLS certificate errors (optional)
        :param use_grpc: Use gRPC instead of HTTP (optional)
        """
        super().__init__(debug, trace, quiet)
        ver_details = Scanner.version_details()
        self.use_grpc = use_grpc
        self.grpc_api = ScanossGrpc(
            url=grpc_url,
            debug=debug,
            quiet=quiet,
            trace=trace,
            api_key=api_key,
            ver_details=ver_details,
            ca_cert=ca_cert,
            proxy=proxy,
            pac=pac,
            grpc_proxy=grpc_proxy,
            timeout=timeout,
            req_headers=req_headers,
            ignore_cert_errors=ignore_cert_errors,
        )
        self.cdx = CycloneDx(debug=self.debug)

    def load_comps(self, json_file: Optional[str] = None, purls: Optional[List[str]] = None) -> Optional[dict]:
        """
        Load the specified components and return a dictionary

        :param json_file: JSON Components file (optional)
        :param purls: list pf PURLs (optional)
        :return: Components Request dictionary or None
        """
        return self.load_purls(json_file, purls, 'components')

    def load_purls(
        self, json_file: Optional[str] = None, purls: Optional[List[str]] = None, field: str = 'purls'
    ) -> Optional[dict]:
        """
        Load the specified purls and return a dictionary

        :param json_file: JSON PURL file (optional)
        :param purls: list of PURLs (optional)
        :param field: Name of the dictionary field to store the purls in (default: 'purls')
        :return: PURL Request dictionary or None
        """
        if json_file:
            result = validate_json_file(json_file)
            if not result.is_valid:
                self.print_stderr(f'ERROR: Problem parsing input JSON: {result.error}')
                return None

            if self.cdx.is_cyclonedx_json(json.dumps(result.data)):
                purl_request = self.cdx.get_purls_request_from_cdx(result.data, field)
            else:
                purl_request = result.data
        elif purls:
            if not all(isinstance(purl, str) for purl in purls):
                self.print_stderr('ERROR: PURLs must be a list of strings.')
                return None
            parsed_purls = []
            for p in purls:
                parsed_purls.append({'purl': p})
            purl_request = {field: parsed_purls}
        else:
            self.print_stderr('ERROR: No purls specified to process.')
            return None
        purl_count = len(purl_request.get(field, []))
        self.print_debug(f'Parsed {field} ({purl_count}): {purl_request}')
        if purl_count == 0:
            self.print_stderr(f'ERROR: No {field} parsed from request.')
            return None
        return purl_request

    def load_json(self, json_file: str = None) -> dict:
        """
        Load the specified json and return a dictionary

        :param json_file: JSON PURL file
        :return: PURL Request dictionary
        """
        if json_file:
            if not os.path.isfile(json_file) or not os.access(json_file, os.R_OK):
                self.print_stderr(f'ERROR: JSON file does not exist, is not a file, or is not readable: {json_file}')
                return None
            with open(json_file, 'r') as f:
                try:
                    return json.loads(f.read())
                except Exception as e:
                    self.print_stderr(f'ERROR: Problem parsing input JSON: {e}')
        return None

    def _open_file_or_sdtout(self, filename):
        """
        Open the given filename if requested, otherwise return STDOUT

        :param filename: filename to open or None to return STDOUT
        :return: file descriptor or None
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

    def get_vulnerabilities(self, json_file: str = None, purls: [] = None, output_file: str = None) -> bool:
        """
        Retrieve any vulnerabilities related to the given PURLs

        :param json_file: PURL JSON request file (optional)
        :param purls: PURL request array (optional)
        :param output_file: output filename (optional). Default: STDOUT
        :return: True on success, False otherwise
        """
        success = False
        purls_request = self.load_comps(json_file, purls)
        if purls_request is None or len(purls_request) == 0:
            return False
        file = self._open_file_or_sdtout(output_file)
        if file is None:
            return False
        self.print_msg('Sending PURLs to Vulnerability API for decoration...')
        response = self.grpc_api.get_vulnerabilities_json(purls_request, use_grpc=self.use_grpc)
        if response:
            print(json.dumps(response, indent=2, sort_keys=True), file=file)
            success = True
            if output_file:
                self.print_msg(f'Results written to: {output_file}')
        self._close_file(output_file, file)
        return success

    def get_semgrep_details(self, json_file: str = None, purls: [] = None, output_file: str = None) -> bool:
        """
        Retrieve the semgrep details for the supplied PURLs

        :param json_file: PURL JSON request file (optional)
        :param purls: PURL request array (optional)
        :param output_file: output filename (optional). Default: STDOUT
        :return: True on success, False otherwise
        """
        success = False
        purls_request = self.load_comps(json_file, purls)
        if purls_request is None or len(purls_request) == 0:
            return False
        file = self._open_file_or_sdtout(output_file)
        if file is None:
            return False
        self.print_msg('Sending PURLs to Semgrep API for decoration...')
        response = self.grpc_api.get_semgrep_json(purls_request, use_grpc=self.use_grpc)
        if response:
            print(json.dumps(response, indent=2, sort_keys=True), file=file)
            success = True
            if output_file:
                self.print_msg(f'Results written to: {output_file}')
        self._close_file(output_file, file)
        return success

    def search_components(  # noqa: PLR0913, PLR0915
        self,
        output_file: str = None,
        json_file: str = None,
        search: str = None,
        vendor: str = None,
        comp: str = None,
        package: str = None,
        limit: int = None,
        offset: int = None,
    ) -> bool:
        """
        Search for a component based on the given search criteria

        :param output_file: output filename (optional). Default: STDOUT
        :param json_file: Search JSON request file (optional)
        :param search: Search for (vendor/component/purl) for a component (overrides vendor/component)
        :param vendor: Vendor to search for
        :param comp: Component to search for
        :param package: Package (purl type) to search for. i.e. github/maven/maven/npn/all - default github
        :param limit: Number of matches to return
        :param offset: Offset to submit to return next (limit) of component matches
        :return: True on success, False otherwise
        """
        success = False
        request: dict
        if json_file:  # Parse the json file to extract the search details
            request = self.load_json(json_file)
            if request is None:
                return False
        else:  # Construct a query dictionary from parameters
            request = {'search': search, 'vendor': vendor, 'component': comp, 'package': package}
            if limit is not None and limit > 0:
                request['limit'] = limit
            if offset is not None and offset > 0:
                request['offset'] = offset

        file = self._open_file_or_sdtout(output_file)
        if file is None:
            return False
        self.print_msg('Sending search data to Components API...')
        response = self.grpc_api.search_components_json(request, use_grpc=self.use_grpc)
        if response:
            print(json.dumps(response, indent=2, sort_keys=True), file=file)
            success = True
            if output_file:
                self.print_msg(f'Results written to: {output_file}')
        self._close_file(output_file, file)
        return success

    def get_component_versions(
        self, output_file: str = None, json_file: str = None, purl: str = None, limit: int = None
    ) -> bool:
        """
        Search for a component versions based on the given search criteria

        :param output_file: output filename (optional). Default: STDOUT
        :param json_file: Search JSON request file (optional)
        :param purl: PURL to retrieve versions for
        :param limit: Number of version to return
        :return: True on success, False otherwise
        """
        success = False
        request: dict
        if json_file:  # Parse the json file to extract the search details
            request = self.load_json(json_file)
            if request is None:
                return False
        else:  # Construct a query dictionary from parameters
            request = {'purl': purl}
            if limit is not None and limit > 0:
                request['limit'] = limit

        file = self._open_file_or_sdtout(output_file)
        if file is None:
            return False
        self.print_msg('Sending PURLs to Component Versions API...')
        response = self.grpc_api.get_component_versions_json(request, use_grpc=self.use_grpc)
        if response:
            print(json.dumps(response, indent=2, sort_keys=True), file=file)
            success = True
            if output_file:
                self.print_msg(f'Results written to: {output_file}')
        self._close_file(output_file, file)
        return success

    def get_provenance_details(
        self, json_file: str = None, purls: [] = None, output_file: str = None, origin: bool = False
    ) -> bool:
        """
        Retrieve the provenance details for the supplied PURLs

        Args:
            json_file (str, optional): Input JSON file. Defaults to None.
            purls (None, optional): PURLs to retrieve provenance details for. Defaults to None.
            output_file (str, optional): Output file. Defaults to None.
            origin (bool, optional): Retrieve origin details. Defaults to False.

        Returns:
            bool: True on success, False otherwise
        """
        success = False
        purls_request = self.load_comps(json_file, purls)
        if purls_request is None or len(purls_request) == 0:
            return False
        file = self._open_file_or_sdtout(output_file)
        if file is None:
            return False
        if origin:
            self.print_msg('Sending PURLs to Geo Provenance Origin API for decoration...')
            response = self.grpc_api.get_provenance_origin(purls_request, use_grpc=self.use_grpc)
        else:
            self.print_msg('Sending PURLs to Geo Provenance Declared API for decoration...')
            response = self.grpc_api.get_provenance_json(purls_request, use_grpc=self.use_grpc)
        if response:
            print(json.dumps(response, indent=2, sort_keys=True), file=file)
            success = True
            if output_file:
                self.print_msg(f'Results written to: {output_file}')
        self._close_file(output_file, file)
        return success

    def get_licenses(self, json_file: str = None, purls: [] = None, output_file: str = None) -> bool:
        """
        Retrieve the license details for the supplied PURLs

        Args:
            json_file (str, optional): Input JSON file. Defaults to None.
            purls (None, optional): PURLs to retrieve license details for. Defaults to None.
            output_file (str, optional): Output file. Defaults to None.

        Returns:
            bool: True on success, False otherwise
        """
        success = False

        purls_request = self.load_purls(json_file, purls)
        if not purls_request:
            return False
        file = self._open_file_or_sdtout(output_file)
        if file is None:
            return False

        # We'll use the new ComponentBatchRequest instead of deprecated PurlRequest for the license api
        component_batch_request = {'components': purls_request.get('purls')}
        response = self.grpc_api.get_licenses(component_batch_request, use_grpc=self.use_grpc)
        if response:
            print(json.dumps(response, indent=2, sort_keys=True), file=file)
            success = True
            if output_file:
                self.print_msg(f'Results written to: {output_file}')
        self._close_file(output_file, file)
        return success
