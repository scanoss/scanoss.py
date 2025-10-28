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

import concurrent.futures
import http.client as http_client
import logging
import os
import sys
import time
import uuid
from dataclasses import dataclass
from enum import Enum, IntEnum
from typing import Dict, Optional
from urllib.parse import urlparse

import grpc
import requests
import urllib3
from google.protobuf.json_format import MessageToDict, ParseDict
from pypac import PACSession
from pypac.parser import PACFile
from pypac.resolver import ProxyResolver
from urllib3.exceptions import InsecureRequestWarning

from scanoss.api.licenses.v2.scanoss_licenses_pb2_grpc import LicenseStub
from scanoss.api.scanning.v2.scanoss_scanning_pb2_grpc import ScanningStub
from scanoss.constants import DEFAULT_TIMEOUT

from . import __version__
from .api.common.v2.scanoss_common_pb2 import (
    ComponentsRequest,
    EchoRequest,
    StatusCode,
    StatusResponse,
)
from .api.components.v2.scanoss_components_pb2 import (
    CompSearchRequest,
    CompVersionRequest,
)
from .api.components.v2.scanoss_components_pb2_grpc import ComponentsStub
from .api.cryptography.v2.scanoss_cryptography_pb2_grpc import CryptographyStub
from .api.dependencies.v2.scanoss_dependencies_pb2 import DependencyRequest
from .api.dependencies.v2.scanoss_dependencies_pb2_grpc import DependenciesStub
from .api.geoprovenance.v2.scanoss_geoprovenance_pb2_grpc import GeoProvenanceStub
from .api.scanning.v2.scanoss_scanning_pb2 import HFHRequest
from .api.semgrep.v2.scanoss_semgrep_pb2_grpc import SemgrepStub
from .api.vulnerabilities.v2.scanoss_vulnerabilities_pb2_grpc import VulnerabilitiesStub
from .scanossbase import ScanossBase

DEFAULT_URL = 'https://api.osskb.org'  # default free service URL
DEFAULT_URL2 = 'https://api.scanoss.com'  # default premium service URL
SCANOSS_GRPC_URL = os.environ.get('SCANOSS_GRPC_URL') if os.environ.get('SCANOSS_GRPC_URL') else DEFAULT_URL
SCANOSS_API_KEY = os.environ.get('SCANOSS_API_KEY') if os.environ.get('SCANOSS_API_KEY') else ''
DEFAULT_URI_PREFIX = '/v2'

MAX_CONCURRENT_REQUESTS = 5  # Maximum number of concurrent requests to make

# REST API endpoint mappings with HTTP methods
REST_ENDPOINTS = {
    'vulnerabilities.GetComponentsVulnerabilities': {'path': '/vulnerabilities/components', 'method': 'POST'},
    'dependencies.Echo': {'path': '/dependencies/echo', 'method': 'POST'},
    'dependencies.GetDependencies': {'path': '/dependencies/dependencies', 'method': 'POST'},
    'cryptography.Echo': {'path': '/cryptography/echo', 'method': 'POST'},
    'cryptography.GetComponentsAlgorithms': {'path': '/cryptography/algorithms/components', 'method': 'POST'},
    'cryptography.GetComponentsAlgorithmsInRange': {
        'path': '/cryptography/algorithms/range/components',
        'method': 'POST',
    },
    'cryptography.GetComponentsEncryptionHints': {'path': '/cryptography/hints/components', 'method': 'POST'},
    'cryptography.GetComponentsHintsInRange': {'path': '/cryptography/hints/components/range', 'method': 'POST'},
    'cryptography.GetComponentsVersionsInRange': {
        'path': '/cryptography/algorithms/versions/range/components',
        'method': 'POST',
    },
    'components.SearchComponents': {'path': '/components/search', 'method': 'GET'},
    'components.GetComponentVersions': {'path': '/components/versions', 'method': 'GET'},
    'geoprovenance.GetCountryContributorsByComponents': {
        'path': '/geoprovenance/countries/components',
        'method': 'POST',
    },
    'geoprovenance.GetOriginByComponents': {'path': '/geoprovenance/origin/components', 'method': 'POST'},
    'licenses.GetComponentsLicenses': {'path': '/licenses/components', 'method': 'POST'},
    'semgrep.GetComponentsIssues': {'path': '/semgrep/issues/components', 'method': 'POST'},
    'scanning.FolderHashScan': {'path': '/scanning/hfh/scan', 'method': 'POST'},
}


class ScanossGrpcError(Exception):
    """
    Custom exception for SCANOSS gRPC errors
    """

    pass


class ScanossGrpcStatusCode(IntEnum):
    """Status codes for SCANOSS gRPC responses"""

    UNSPECIFIED = 0
    SUCCESS = 1
    SUCCEEDED_WITH_WARNINGS = 2
    WARNING = 3
    FAILED = 4


class ScanossRESTStatusCode(Enum):
    """Status codes for SCANOSS REST responses"""

    UNSPECIFIED = 'UNSPECIFIED'
    SUCCESS = 'SUCCESS'
    SUCCEEDED_WITH_WARNINGS = 'SUCCEEDED_WITH_WARNINGS'
    WARNING = 'WARNING'
    FAILED = 'FAILED'


class ScanossGrpc(ScanossBase):
    """
    Client for gRPC functionality
    """

    def __init__(  # noqa: PLR0912, PLR0913, PLR0915
        self,
        url: Optional[str] = None,
        debug: bool = False,
        trace: bool = False,
        quiet: bool = False,
        ca_cert: Optional[str] = None,
        api_key: Optional[str] = None,
        ver_details: Optional[str] = None,
        timeout: int = 600,
        proxy: Optional[str] = None,
        grpc_proxy: Optional[str] = None,
        pac: Optional[PACFile] = None,
        req_headers: Optional[dict] = None,
        ignore_cert_errors: bool = False,
        use_grpc: Optional[bool] = False,
    ):
        """

        :param url:
        :param debug:
        :param trace:
        :param quiet:
        :param ca_cert:

        To set a custom certificate use:
            GRPC_DEFAULT_SSL_ROOTS_FILE_PATH=/path/to/certs/cert.pem
        More details here: https://grpc.github.io/grpc/cpp/grpc__security__constants_8h.html
                           https://github.com/grpc/grpc/blob/master/doc/environment_variables.md
        To enable a Proxy use:
            grpc_proxy='http://<ip>:<port>'
        """
        super().__init__(debug, trace, quiet)
        self.api_key = api_key if api_key else SCANOSS_API_KEY
        self.timeout = timeout
        self.proxy = proxy
        self.grpc_proxy = grpc_proxy
        self.pac = pac
        self.metadata = []
        self.ignore_cert_errors = ignore_cert_errors
        self.use_grpc = use_grpc
        self.req_headers = req_headers if req_headers else {}
        self.headers = {}
        self.retry_limit = 2  # default retry limit

        if self.api_key:
            self.metadata.append(('x-api-key', api_key))  # Set API key if we have one
            self.headers['X-Session'] = self.api_key
            self.headers['x-api-key'] = self.api_key
        if ver_details:
            self.metadata.append(('x-scanoss-client', ver_details))
            self.headers['x-scanoss-client'] = ver_details
        user_agent = f'scanoss-py/{__version__}'
        self.metadata.append(('user-agent', user_agent))
        self.headers['User-Agent'] = user_agent
        self.headers['user-agent'] = user_agent
        self.headers['Content-Type'] = 'application/json'
        # Set the correct URL/API key combination
        self.url = url if url else SCANOSS_GRPC_URL
        if self.api_key and not url and not os.environ.get('SCANOSS_GRPC_URL'):
            self.url = DEFAULT_URL2  # API key specific and no alternative URL, so use the default premium
        self.load_generic_headers(url)
        self.url = self.url.lower()
        self.orig_url = self.url.strip().rstrip('/')  # Used for proxy lookup
        # REST setup
        if self.trace:
            logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
            http_client.HTTPConnection.debuglevel = 1
        if pac and not proxy:  # Set up a PAC session if requested (and no proxy has been explicitly set)
            self.print_debug('Setting up PAC session...')
            self.session = PACSession(pac=pac)
        else:
            self.session = requests.sessions.Session()
        if self.ignore_cert_errors:
            self.print_debug('Ignoring cert errors...')
            urllib3.disable_warnings(InsecureRequestWarning)
            self.session.verify = False
        elif ca_cert:
            self.session.verify = ca_cert
        self.proxies = {'https': proxy, 'http': proxy} if proxy else None
        if self.proxies:
            self.session.proxies = self.proxies

        secure = True if self.url.startswith('https:') else False  # Is it a secure connection?
        if self.url.startswith('http'):
            u = urlparse(self.url)
            port = u.port
            if port is None:
                port = 443 if u.scheme == 'https' else 80  # Set the default port number if it's not available
            self.url = f'{u.hostname}:{port}'
        cert_data = None
        if ca_cert is not None:
            secure = True
            cert_data = ScanossGrpc._load_cert(ca_cert)
        self.print_debug(f'Setting up (secure: {secure}) connection to {self.url}...')
        self._get_proxy_config()
        if not secure:  # insecure connection
            self.comp_search_stub = ComponentsStub(grpc.insecure_channel(self.url))
            self.crypto_stub = CryptographyStub(grpc.insecure_channel(self.url))
            self.dependencies_stub = DependenciesStub(grpc.insecure_channel(self.url))
            self.semgrep_stub = SemgrepStub(grpc.insecure_channel(self.url))
            self.vuln_stub = VulnerabilitiesStub(grpc.insecure_channel(self.url))
            self.provenance_stub = GeoProvenanceStub(grpc.insecure_channel(self.url))
            self.scanning_stub = ScanningStub(grpc.insecure_channel(self.url))
            self.license_stub = LicenseStub(grpc.insecure_channel(self.url))
        else:
            if ca_cert is not None:
                credentials = grpc.ssl_channel_credentials(cert_data)  # secure with specified certificate
            else:
                credentials = grpc.ssl_channel_credentials()  # secure connection with default certificate
            self.comp_search_stub = ComponentsStub(grpc.secure_channel(self.url, credentials))
            self.crypto_stub = CryptographyStub(grpc.secure_channel(self.url, credentials))
            self.dependencies_stub = DependenciesStub(grpc.secure_channel(self.url, credentials))
            self.semgrep_stub = SemgrepStub(grpc.secure_channel(self.url, credentials))
            self.vuln_stub = VulnerabilitiesStub(grpc.secure_channel(self.url, credentials))
            self.provenance_stub = GeoProvenanceStub(grpc.secure_channel(self.url, credentials))
            self.scanning_stub = ScanningStub(grpc.secure_channel(self.url, credentials))
            self.license_stub = LicenseStub(grpc.secure_channel(self.url, credentials))

    @classmethod
    def _load_cert(cls, cert_file: str) -> bytes:
        with open(cert_file, 'rb') as f:
            return f.read()

    def deps_echo(self, message: str = 'Hello there!') -> Optional[dict]:
        """
        Send Echo message to the Dependency service
        :param self:
        :param message: Message to send (default: Hello there!)
        :return: echo or None
        """
        return self._call_api('dependencies.Echo', self.dependencies_stub.Echo, {'message': message}, EchoRequest)

    def crypto_echo(self, message: str = 'Hello there!') -> Optional[dict]:
        """
        Send Echo message to the Cryptography service
        :param self:
        :param message: Message to send (default: Hello there!)
        :return: echo or None
        """
        return self._call_api('cryptography.Echo', self.crypto_stub.Echo, {'message': message}, EchoRequest)

    def get_dependencies(self, dependencies: Optional[dict] = None, depth: int = 1) -> Optional[dict]:
        if not dependencies:
            self.print_stderr('ERROR: No dependency data supplied to submit to the API.')
            return None
        resp = self.get_dependencies_json(dependencies, depth)
        if not resp:
            self.print_stderr(f'ERROR: No response for dependency request: {dependencies}')
        return resp

    def get_dependencies_json(self, dependencies: dict, depth: int = 1) -> Optional[dict]:
        """
        Client function to call the rpc for GetDependencies
        :param dependencies: Message to send to the service
        :param depth: depth of sub-dependencies to search (default: 1)
        :return: Server response or None
        """
        if not dependencies:
            self.print_stderr('ERROR: No message supplied to send to gRPC service.')
            return None
        files_json = dependencies.get('files')
        if files_json is None or len(files_json) == 0:
            self.print_stderr('ERROR: No dependency data supplied to send to decoration service.')
            return None
        all_responses = []
        # Process the dependency files in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_CONCURRENT_REQUESTS) as executor:
            future_to_file = {
                executor.submit(self._process_dep_file, file, depth, self.use_grpc): file for file in files_json
            }
            for future in concurrent.futures.as_completed(future_to_file):
                response = future.result()
                if response:
                    all_responses.append(response)
        # End of concurrent processing
        success_status = 'SUCCESS'
        merged_response = {'files': [], 'status': {'status': success_status, 'message': 'Success'}}
        # Merge the responses
        for response in all_responses:
            if response:
                if 'files' in response and len(response['files']) > 0:
                    merged_response['files'].append(response['files'][0])
                # Overwrite the status if any of the responses was not successful
                if 'status' in response and response['status']['status'] != success_status:
                    merged_response['status'] = response['status']
        return merged_response

    def _process_dep_file(self, file, depth: int = 1, use_grpc: Optional[bool] = None) -> Optional[dict]:
        """
        Process a single dependency file using either gRPC or REST

        Args:
            file: dependency file purls
            depth: depth to search (default: 1)
            use_grpc: Whether to use gRPC or REST (None = use instance default)

        Returns:
            response JSON or None
        """
        file_request = {'files': [file], 'depth': depth}

        return self._call_api(
            'dependencies.GetDependencies',
            self.dependencies_stub.GetDependencies,
            file_request,
            DependencyRequest,
            'Sending dependency data for decoration (rqId: {rqId})...',
            use_grpc=use_grpc,
        )

    def get_vulnerabilities_json(self, purls: Optional[dict] = None, use_grpc: Optional[bool] = None) -> Optional[dict]:
        """
        Client function to call the rpc for Vulnerability GetVulnerabilities
        It will either use REST (default) or gRPC

        Args:
            purls (dict): Message to send to the service

        Returns:
            Server response or None
        """
        return self._call_api(
            'vulnerabilities.GetComponentsVulnerabilities',
            self.vuln_stub.GetComponentsVulnerabilities,
            purls,
            ComponentsRequest,
            'Sending vulnerability data for decoration (rqId: {rqId})...',
            use_grpc=use_grpc,
        )

    def get_semgrep_json(self, purls: Optional[dict] = None, use_grpc: Optional[bool] = None) -> Optional[dict]:
        """
        Client function to call the rpc for Semgrep GetIssues

        Args:
            purls (dict): Message to send to the service
            use_grpc (bool): Whether to use gRPC or REST

        Returns:
            Server response or None
        """
        return self._call_api(
            'semgrep.GetComponentsIssues',
            self.semgrep_stub.GetComponentsIssues,
            purls,
            ComponentsRequest,
            'Sending semgrep data for decoration (rqId: {rqId})...',
            use_grpc=use_grpc,
        )

    def search_components_json(self, search: dict, use_grpc: Optional[bool] = None) -> Optional[dict]:
        """
        Client function to call the rpc for Components SearchComponents

        Args:
            search (dict): Message to send to the service
        Returns:
            Server response or None
        """
        return self._call_api(
            'components.SearchComponents',
            self.comp_search_stub.SearchComponents,
            search,
            CompSearchRequest,
            'Sending component search data for decoration (rqId: {rqId})...',
            use_grpc=use_grpc,
        )

    def get_component_versions_json(self, search: dict, use_grpc: Optional[bool] = None) -> Optional[dict]:
        """
        Client function to call the rpc for Components GetComponentVersions

        Args:
            search (dict): Message to send to the service
        Returns:
            Server response or None
        """
        return self._call_api(
            'components.GetComponentVersions',
            self.comp_search_stub.GetComponentVersions,
            search,
            CompVersionRequest,
            'Sending component version data for decoration (rqId: {rqId})...',
            use_grpc=use_grpc,
        )

    def folder_hash_scan(self, request: Dict, use_grpc: Optional[bool] = None) -> Optional[Dict]:
        """
        Client function to call the rpc for Folder Hashing Scan

        Args:
            request (Dict): Folder Hash Request
            use_grpc (Optional[bool]): Whether to use gRPC or REST API

        Returns:
            Optional[Dict]: Folder Hash Response, or None if the request was not succesfull
        """
        return self._call_api(
            'scanning.FolderHashScan',
            self.scanning_stub.FolderHashScan,
            request,
            HFHRequest,
            'Sending folder hash scan data (rqId: {rqId})...',
            use_grpc=use_grpc,
        )

    def _call_api(
        self,
        endpoint_key: str,
        rpc_method,
        request_input,
        request_type,
        debug_msg: Optional[str] = None,
        use_grpc: Optional[bool] = None,
    ) -> Optional[Dict]:
        """
        Unified method to call either gRPC or REST API based on configuration

        Args:
            endpoint_key (str): The key to lookup the REST endpoint in REST_ENDPOINTS
            rpc_method: The gRPC stub method (used only if use_grpc is True)
            request_input: Either a dict or a gRPC request object
            request_type: The type of the gRPC request object (used only if use_grpc is True)
            debug_msg (str, optional): Debug message template that can include {rqId} placeholder
            use_grpc (bool, optional): Override the instance's use_grpc setting. If None, uses self.use_grpc

        Returns:
            dict: The parsed response as a dictionary, or None if something went wrong
        """
        if not request_input:
            self.print_stderr('ERROR: No message supplied to send to service.')
            return None

        # Determine whether to use gRPC or REST
        use_grpc_flag = use_grpc if use_grpc is not None else self.use_grpc

        if use_grpc_flag:
            return self._call_rpc(rpc_method, request_input, request_type, debug_msg)
        else:
            # For REST, we only need the dict input
            if not isinstance(request_input, dict):
                request_input = MessageToDict(request_input, preserving_proto_field_name=True)
            return self._call_rest(endpoint_key, request_input, debug_msg)

    def _call_rpc(self, rpc_method, request_input, request_type, debug_msg: Optional[str] = None) -> Optional[Dict]:
        """
        Call a gRPC method and return the response as a dictionary

        Args:
            rpc_method (): The gRPC stub method
            request_input (): Either a dict or a gRPC request object.
            request_type (): The type of the gRPC request object.
            debug_msg (str, optional): Debug message template that can include {rqId} placeholder.

        Returns:
            dict: The parsed gRPC response as a dictionary, or None if something went wrong
        """
        request_id = str(uuid.uuid4())
        if isinstance(request_input, dict):
            request_obj = ParseDict(request_input, request_type())
        else:
            request_obj = request_input
        metadata = self.metadata[:] + [('x-request-id', request_id)]
        if debug_msg:
            self.print_debug(debug_msg.format(rqId=request_id))
        try:
            resp = rpc_method(request_obj, metadata=metadata, timeout=self.timeout)
        except grpc.RpcError as e:
            raise ScanossGrpcError(
                f'{e.__class__.__name__} while sending gRPC message (rqId: {request_id}): {e.details()}'
            )
        if resp and not self._check_status_response_grpc(resp.status, request_id):
            return None

        resp_dict = MessageToDict(resp, preserving_proto_field_name=True)
        return resp_dict

    def _check_status_response_grpc(self, status_response: StatusResponse, request_id: str = None) -> bool:
        """
        Check the response object to see if the command was successful or not
        :param status_response: Status Response
        :return: True if successful, False otherwise
        """

        if not status_response:
            self.print_stderr(f'Warning: No status response supplied (rqId: {request_id}). Assuming it was ok.')
            return True
        self.print_debug(f'Checking response status (rqId: {request_id}): {status_response}')
        status_code: StatusCode = status_response.status
        if status_code > ScanossGrpcStatusCode.SUCCESS:
            ret_val = False  # default to failed
            msg = 'Unsuccessful'
            if status_code == ScanossGrpcStatusCode.SUCCEEDED_WITH_WARNINGS:
                msg = 'Succeeded with warnings'
                ret_val = True  # No need to fail as it succeeded with warnings
            elif status_code == ScanossGrpcStatusCode.WARNING:
                msg = 'Failed with warnings'
            self.print_stderr(f'{msg} (rqId: {request_id} - status: {status_code}): {status_response.message}')
            return ret_val
        return True

    def check_status_response_rest(self, status_dict: dict, request_id: Optional[str] = None) -> bool:
        """
        Check the REST response dictionary to see if the command was successful or not

        Args:
            status_dict (dict): Status dictionary from REST response containing 'status' and 'message' keys
            request_id (str, optional): Request ID for logging
        Returns:
            bool: True if successful, False otherwise
        """
        if not status_dict:
            self.print_stderr(f'Warning: No status response supplied (rqId: {request_id}). Assuming it was ok.')
            return True

        if request_id:
            self.print_debug(f'Checking response status (rqId: {request_id}): {status_dict}')

        # Get status from dictionary - it can be either a string or nested dict
        status = status_dict.get('status')
        message = status_dict.get('message', '')
        ret_val = True

        # Handle case where status might be a string directly
        if isinstance(status, str):
            status_str = status.upper()
            if status_str == ScanossRESTStatusCode.SUCCESS.value:
                ret_val = True
            elif status_str == ScanossRESTStatusCode.SUCCEEDED_WITH_WARNINGS.value:
                self.print_stderr(f'Succeeded with warnings (rqId: {request_id}): {message}')
                ret_val = True
            elif status_str == ScanossRESTStatusCode.WARNING.value:
                self.print_stderr(f'Failed with warnings (rqId: {request_id}): {message}')
                ret_val = False
            elif status_str == ScanossRESTStatusCode.FAILED.value:
                self.print_stderr(f'Unsuccessful (rqId: {request_id}): {message}')
                ret_val = False
            else:
                self.print_debug(f'Unknown status "{status_str}" (rqId: {request_id}). Assuming success.')
                ret_val = True

        # Otherwise asume success
        self.print_debug(f'Unexpected status type {type(status)} (rqId: {request_id}). Assuming success.')
        return ret_val

    def _get_proxy_config(self):
        """
        Set the grpc_proxy/http_proxy/https_proxy environment variables if PAC file has been specified
        or if an explicit proxy has been supplied
        :param self:
        """
        if self.grpc_proxy:
            self.print_debug('Setting GRPC (grpc_proxy) proxy...')
            os.environ['grpc_proxy'] = self.grpc_proxy
        elif self.proxy:
            self.print_debug('Setting GRPC (http_proxy/https_proxy) proxies...')
            os.environ['http_proxy'] = self.proxy
            os.environ['https_proxy'] = self.proxy
        elif self.pac:
            self.print_debug(f'Attempting to get GRPC proxy details from PAC for {self.orig_url}...')
            resolver = ProxyResolver(self.pac)
            proxies = resolver.get_proxy_for_requests(self.orig_url)
            if proxies:
                self.print_trace(f'Setting proxies: {proxies}')
            os.environ['http_proxy'] = proxies.get('http') or ''
            os.environ['https_proxy'] = proxies.get('https') or ''

    def get_provenance_json(self, purls: dict, use_grpc: Optional[bool] = None) -> Optional[Dict]:
        """
        Client function to call the rpc for GetComponentContributors

        Args:
            purls (dict): ComponentsRequest
            use_grpc (bool): Whether to use gRPC or REST (None = use instance default)

        Returns:
            dict: JSON response or None
        """
        return self._call_api(
            'geoprovenance.GetCountryContributorsByComponents',
            self.provenance_stub.GetCountryContributorsByComponents,
            purls,
            ComponentsRequest,
            'Sending data for provenance decoration (rqId: {rqId})...',
            use_grpc=use_grpc,
        )

    def get_provenance_origin(self, request: Dict, use_grpc: Optional[bool] = None) -> Optional[Dict]:
        """
        Client function to call the rpc for GetOriginByComponents

        Args:
            request (Dict): GetOriginByComponents Request

        Returns:
            Optional[Dict]: OriginResponse, or None if the request was not successfull
        """
        return self._call_api(
            'geoprovenance.GetOriginByComponents',
            self.provenance_stub.GetOriginByComponents,
            request,
            ComponentsRequest,
            'Sending data for provenance origin decoration (rqId: {rqId})...',
            use_grpc=use_grpc,
        )

    def get_crypto_algorithms_for_purl(self, request: Dict, use_grpc: Optional[bool] = None) -> Optional[Dict]:
        """
        Client function to call the rpc for GetComponentsAlgorithms for a list of purls

        Args:
            request (Dict): ComponentsRequest
            use_grpc (Optional[bool]): Whether to use gRPC or REST (None = use instance default)

        Returns:
            Optional[Dict]: AlgorithmResponse, or None if the request was not successfull
        """
        return self._call_api(
            'cryptography.GetComponentsAlgorithms',
            self.crypto_stub.GetComponentsAlgorithms,
            request,
            ComponentsRequest,
            'Sending data for cryptographic algorithms decoration (rqId: {rqId})...',
            use_grpc=use_grpc,
        )

    def get_crypto_algorithms_in_range_for_purl(self, request: Dict, use_grpc: Optional[bool] = None) -> Optional[Dict]:
        """
        Client function to call the rpc for GetComponentsAlgorithmsInRange for a list of purls

        Args:
            request (Dict): ComponentsRequest
            use_grpc (Optional[bool]): Whether to use gRPC or REST (None = use instance default)

        Returns:
            Optional[Dict]: AlgorithmsInRangeResponse, or None if the request was not successfull
        """
        return self._call_api(
            'cryptography.GetComponentsAlgorithmsInRange',
            self.crypto_stub.GetComponentsAlgorithmsInRange,
            request,
            ComponentsRequest,
            'Sending data for cryptographic algorithms in range decoration (rqId: {rqId})...',
            use_grpc=use_grpc,
        )

    def get_encryption_hints_for_purl(self, request: Dict, use_grpc: Optional[bool] = None) -> Optional[Dict]:
        """
        Client function to call the rpc for GetComponentsEncryptionHints for a list of purls

        Args:
            request (Dict): ComponentsRequest
            use_grpc (Optional[bool]): Whether to use gRPC or REST (None = use instance default)

        Returns:
            Optional[Dict]: HintsResponse, or None if the request was not successfull
        """
        return self._call_api(
            'cryptography.GetComponentsEncryptionHints',
            self.crypto_stub.GetComponentsEncryptionHints,
            request,
            ComponentsRequest,
            'Sending data for encryption hints decoration (rqId: {rqId})...',
            use_grpc=use_grpc,
        )

    def get_encryption_hints_in_range_for_purl(self, request: Dict, use_grpc: Optional[bool] = None) -> Optional[Dict]:
        """
        Client function to call the rpc for GetComponentsHintsInRange for a list of purls

        Args:
            request (Dict): ComponentsRequest
            use_grpc (Optional[bool]): Whether to use gRPC or REST (None = use instance default)

        Returns:
            Optional[Dict]: HintsInRangeResponse, or None if the request was not successfull
        """
        return self._call_api(
            'cryptography.GetComponentsHintsInRange',
            self.crypto_stub.GetComponentsHintsInRange,
            request,
            ComponentsRequest,
            'Sending data for encryption hints in range decoration (rqId: {rqId})...',
            use_grpc=use_grpc,
        )

    def get_versions_in_range_for_purl(self, request: Dict, use_grpc: Optional[bool] = None) -> Optional[Dict]:
        """
        Client function to call the rpc for GetComponentsVersionsInRange for a list of purls

        Args:
            request (Dict): ComponentsRequest
            use_grpc (Optional[bool]): Whether to use gRPC or REST (None = use instance default)

        Returns:
            Optional[Dict]: VersionsInRangeResponse, or None if the request was not successfull
        """
        return self._call_api(
            'cryptography.GetComponentsVersionsInRange',
            self.crypto_stub.GetComponentsVersionsInRange,
            request,
            ComponentsRequest,
            'Sending data for cryptographic versions in range decoration (rqId: {rqId})...',
            use_grpc=use_grpc,
        )

    def get_licenses(self, request: Dict, use_grpc: Optional[bool] = None) -> Optional[Dict]:
        """
        Client function to call the rpc for Licenses GetComponentsLicenses
        It will either use REST (default) or gRPC depending on the use_grpc flag

        Args:
            request (Dict): ComponentsRequest
        Returns:
            Optional[Dict]: ComponentsLicenseResponse, or None if the request was not successfull
        """
        return self._call_api(
            'licenses.GetComponentsLicenses',
            self.license_stub.GetComponentsLicenses,
            request,
            ComponentsRequest,
            'Sending data for license decoration (rqId: {rqId})...',
            use_grpc=use_grpc,
        )

    def load_generic_headers(self, url: Optional[str] = None):
        """
        Adds custom headers from req_headers to metadata.

        If x-api-key is present and no URL is configured (directly or via
        environment), sets URL to the premium endpoint (DEFAULT_URL2).
        """
        if self.req_headers:  # Load generic headers
            for key, value in self.req_headers.items():
                if key == 'x-api-key':  # Set premium URL if x-api-key header is set
                    if not url and not os.environ.get('SCANOSS_GRPC_URL'):
                        self.url = DEFAULT_URL2  # API key specific and no alternative URL, so use the default premium
                    self.api_key = value
                self.metadata.append((key, value))
                self.headers[key] = value

    #
    # End of gRPC Client Functions
    #
    # Start of REST Client Functions
    #

    def _rest_get(self, uri: str, request_id: str, params: Optional[dict] = None) -> Optional[dict]:
        """
        Send a GET request to the specified URI with optional query parameters.

        Args:
            uri (str): URI to send GET request to
            request_id (str): request id
            params (dict, optional): Optional query parameters as dictionary

        Returns:
            dict: JSON response or None
        """
        if not uri:
            self.print_stderr('Error: Missing URI. Cannot perform GET request.')
            return None
        self.print_trace(f'Sending REST GET request to {uri}...')
        headers = self.headers.copy()
        headers['x-request-id'] = request_id
        retry = 0
        while retry <= self.retry_limit:
            retry += 1
            try:
                response = self.session.get(uri, headers=headers, params=params, timeout=self.timeout)
                response.raise_for_status()  # Raises an HTTPError for bad responses
                return response.json()
            except (requests.exceptions.SSLError, requests.exceptions.ProxyError) as e:
                self.print_stderr(f'ERROR: Exception ({e.__class__.__name__}) sending GET request - {e}.')
                raise Exception(f'ERROR: The SCANOSS API GET request failed for {uri}') from e
            except requests.exceptions.HTTPError as e:
                self.print_stderr(f'ERROR: HTTP error sending GET request ({request_id}): {e}')
                raise Exception(
                    f'ERROR: The SCANOSS API GET request failed with status {e.response.status_code} for {uri}'
                ) from e
            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
                if retry > self.retry_limit:  # Timed out retry_limit or more times, fail
                    self.print_stderr(f'ERROR: {e.__class__.__name__} sending GET request ({request_id}): {e}')
                    raise Exception(
                        f'ERROR: The SCANOSS API GET request timed out ({e.__class__.__name__}) for {uri}'
                    ) from e
                else:
                    self.print_stderr(f'Warning: {e.__class__.__name__} communicating with {self.url}. Retrying...')
                    time.sleep(5)
            except requests.exceptions.RequestException as e:
                self.print_stderr(f'Error: Problem sending GET request to {uri}: {e}')
                raise Exception(f'ERROR: The SCANOSS API GET request failed for {uri}') from e
            except Exception as e:
                self.print_stderr(
                    f'ERROR: Exception ({e.__class__.__name__}) sending GET request ({request_id}) to {uri}: {e}'
                )
                raise Exception(f'ERROR: The SCANOSS API GET request failed for {uri}') from e
        return None

    def _rest_post(self, uri: str, request_id: str, data: dict) -> Optional[dict]:
        """
        Post the specified data to the given URI.

        Args:
            uri (str): URI to post to
            request_id (str): request id
            data (dict): json data to post

        Returns:
            dict: JSON response or None
        """
        if not uri:
            self.print_stderr('Error: Missing URI. Cannot search for project.')
            return None
        self.print_trace(f'Sending REST POST data to {uri}...')
        headers = self.headers.copy()
        headers['x-request-id'] = request_id
        retry = 0
        while retry <= self.retry_limit:
            retry += 1
            try:
                response = self.session.post(uri, headers=headers, json=data, timeout=self.timeout)
                response.raise_for_status()  # Raises an HTTPError for bad responses
                return response.json()
            except (requests.exceptions.SSLError, requests.exceptions.ProxyError) as e:
                self.print_stderr(f'ERROR: Exception ({e.__class__.__name__}) POSTing data - {e}.')
                raise Exception(f'ERROR: The SCANOSS Decoration API request failed for {uri}') from e
            except requests.exceptions.HTTPError as e:
                self.print_stderr(f'ERROR: HTTP error POSTing data ({request_id}): {e}')
                raise Exception(
                    f'ERROR: The SCANOSS Decoration API request failed with status {e.response.status_code} for {uri}'
                ) from e
            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
                if retry > self.retry_limit:  # Timed out retry_limit or more times, fail
                    self.print_stderr(f'ERROR: {e.__class__.__name__} POSTing decoration data ({request_id}): {e}')
                    raise Exception(
                        f'ERROR: The SCANOSS Decoration API request timed out ({e.__class__.__name__}) for {uri}'
                    ) from e
                else:
                    self.print_stderr(f'Warning: {e.__class__.__name__} communicating with {self.url}. Retrying...')
                    time.sleep(5)
            except requests.exceptions.RequestException as e:
                self.print_stderr(f'Error: Problem posting data to {uri}: {e}')
                raise Exception(f'ERROR: The SCANOSS Decoration API request failed for {uri}') from e
            except Exception as e:
                self.print_stderr(
                    f'ERROR: Exception ({e.__class__.__name__}) POSTing data ({request_id}) to {uri}: {e}'
                )
                raise Exception(f'ERROR: The SCANOSS Decoration API request failed for {uri}') from e
        return None

    def _call_rest(self, endpoint_key: str, request_input: dict, debug_msg: Optional[str] = None) -> Optional[Dict]:
        """
        Call a REST endpoint and return the response as a dictionary

        Args:
            endpoint_key (str): The key to lookup the REST endpoint in REST_ENDPOINTS
            request_input (dict): The request data to send
            debug_msg (str, optional): Debug message template that can include {rqId} placeholder.

        Returns:
            dict: The parsed REST response as a dictionary, or None if something went wrong
        """
        if endpoint_key not in REST_ENDPOINTS:
            raise ScanossGrpcError(f'Unknown REST endpoint key: {endpoint_key}')

        endpoint_config = REST_ENDPOINTS[endpoint_key]
        endpoint_path = endpoint_config['path']
        method = endpoint_config['method']
        endpoint_url = f'{self.orig_url}{DEFAULT_URI_PREFIX}{endpoint_path}'
        request_id = str(uuid.uuid4())

        if debug_msg:
            self.print_debug(debug_msg.format(rqId=request_id))

        if method == 'GET':
            response = self._rest_get(endpoint_url, request_id, params=request_input)
        else:  # POST
            response = self._rest_post(endpoint_url, request_id, request_input)

        if response and 'status' in response and not self.check_status_response_rest(response['status'], request_id):
            return None

        return response


#
# End of ScanossGrpc Class
#


@dataclass
class GrpcConfig:
    url: str = DEFAULT_URL
    api_key: Optional[str] = SCANOSS_API_KEY
    debug: Optional[bool] = False
    trace: Optional[bool] = False
    quiet: Optional[bool] = False
    ver_details: Optional[str] = None
    ca_cert: Optional[str] = None
    timeout: Optional[int] = DEFAULT_TIMEOUT
    proxy: Optional[str] = None
    grpc_proxy: Optional[str] = None
    pac: Optional[PACFile] = None
    req_headers: Optional[dict] = None


def create_grpc_config_from_args(args) -> GrpcConfig:
    return GrpcConfig(
        url=getattr(args, 'api2url', DEFAULT_URL),
        api_key=getattr(args, 'key', SCANOSS_API_KEY),
        debug=getattr(args, 'debug', False),
        trace=getattr(args, 'trace', False),
        quiet=getattr(args, 'quiet', False),
        ver_details=getattr(args, 'ver_details', None),
        ca_cert=getattr(args, 'ca_cert', None),
        timeout=getattr(args, 'timeout', DEFAULT_TIMEOUT),
        proxy=getattr(args, 'proxy', None),
        grpc_proxy=getattr(args, 'grpc_proxy', None),
    )


#
# End of GrpcConfig class
#
