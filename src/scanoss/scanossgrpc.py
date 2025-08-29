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
import json
import logging
import os
import sys
import time
import uuid
from dataclasses import dataclass
from enum import IntEnum
import requests
from typing import Dict, Optional
from urllib.parse import urlparse
import http.client as http_client
import urllib3

import grpc
from google.protobuf.json_format import MessageToDict, ParseDict
from pypac import PACSession
from pypac.parser import PACFile
from pypac.resolver import ProxyResolver
from urllib3.exceptions import InsecureRequestWarning

from scanoss.api.scanning.v2.scanoss_scanning_pb2_grpc import ScanningStub
from scanoss.constants import DEFAULT_TIMEOUT

from . import __version__
from .api.common.v2.scanoss_common_pb2 import (
    EchoRequest,
    EchoResponse,
    PurlRequest,
    StatusCode,
    StatusResponse,
    ComponentsRequest,
)
from .api.components.v2.scanoss_components_pb2 import (
    CompSearchRequest,
    CompSearchResponse,
    CompVersionRequest,
    CompVersionResponse,
)
from .api.components.v2.scanoss_components_pb2_grpc import ComponentsStub
from .api.cryptography.v2.scanoss_cryptography_pb2_grpc import CryptographyStub
from .api.dependencies.v2.scanoss_dependencies_pb2 import DependencyRequest
from .api.dependencies.v2.scanoss_dependencies_pb2_grpc import DependenciesStub
from .api.geoprovenance.v2.scanoss_geoprovenance_pb2 import ContributorResponse
from .api.geoprovenance.v2.scanoss_geoprovenance_pb2_grpc import GeoProvenanceStub
from .api.scanning.v2.scanoss_scanning_pb2 import HFHRequest
from .api.semgrep.v2.scanoss_semgrep_pb2 import SemgrepResponse
from .api.semgrep.v2.scanoss_semgrep_pb2_grpc import SemgrepStub
from .api.vulnerabilities.v2.scanoss_vulnerabilities_pb2 import ComponentsVulnerabilityResponse
from .api.vulnerabilities.v2.scanoss_vulnerabilities_pb2_grpc import VulnerabilitiesStub
from .scanossbase import ScanossBase

DEFAULT_URL = 'https://api.osskb.org'  # default free service URL
DEFAULT_URL2 = 'https://api.scanoss.com'  # default premium service URL
SCANOSS_GRPC_URL = os.environ.get('SCANOSS_GRPC_URL') if os.environ.get('SCANOSS_GRPC_URL') else DEFAULT_URL
SCANOSS_API_KEY = os.environ.get('SCANOSS_API_KEY') if os.environ.get('SCANOSS_API_KEY') else ''
DEFAULT_URI_PREFIX = '/v2'

MAX_CONCURRENT_REQUESTS = 5 # Maximum number of concurrent requests to make


class ScanossGrpcError(Exception):
    """
    Custom exception for SCANOSS gRPC errors
    """
    pass


class ScanossGrpcStatusCode(IntEnum):
    """Status codes for SCANOSS gRPC responses"""
    SUCCESS = 1
    SUCCESS_WITH_WARNINGS = 2
    FAILED_WITH_WARNINGS = 3
    FAILED = 4


class ScanossGrpc(ScanossBase):
    """
    Client for gRPC functionality
    """

    def __init__(  # noqa: PLR0913, PLR0915
        self,
        url: str = None,
        debug: bool = False,
        trace: bool = False,
        quiet: bool = False,
        ca_cert: str = None,
        api_key: str = None,
        ver_details: str = None,
        timeout: int = 600,
        proxy: str = None,
        grpc_proxy: str = None,
        pac: PACFile = None,
        req_headers: dict = None,
        ignore_cert_errors: bool = False,
        use_grpc: bool = False,
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
        self.url = url
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
        self.metadata.append(('user-agent', f'scanoss-py/{__version__}'))
        self.headers['User-Agent'] = f'scanoss-py/{__version__}'
        self.headers['user-agent'] = f'scanoss-py/{__version__}'
        self.headers['Content-Type'] = 'application/json'
        self.load_generic_headers()

        self.url = url if url else SCANOSS_GRPC_URL
        if self.api_key and not url and not os.environ.get('SCANOSS_GRPC_URL'):
            self.url = DEFAULT_URL2  # API key specific and no alternative URL, so use the default premium
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

    @classmethod
    def _load_cert(cls, cert_file: str) -> bytes:
        with open(cert_file, 'rb') as f:
            return f.read()

    def deps_echo(self, message: str = 'Hello there!') -> str:
        """
        Send Echo message to the Dependency service
        :param self:
        :param message: Message to send (default: Hello there!)
        :return: echo or None
        """
        request_id = str(uuid.uuid4())
        resp: EchoResponse
        try:
            metadata = self.metadata[:]
            metadata.append(('x-request-id', request_id))  # Set a Request ID
            resp = self.dependencies_stub.Echo(EchoRequest(message=message), metadata=metadata, timeout=3)
        except Exception as e:
            self.print_stderr(
                f'ERROR: {e.__class__.__name__} Problem encountered sending gRPC message (rqId: {request_id}): {e}'
            )
        else:
            if resp:
                return resp.message
            self.print_stderr(f'ERROR: Problem sending Echo request ({message}) to {self.url}. rqId: {request_id}')
        return None

    def crypto_echo(self, message: str = 'Hello there!') -> str:
        """
        Send Echo message to the Cryptography service
        :param self:
        :param message: Message to send (default: Hello there!)
        :return: echo or None
        """
        request_id = str(uuid.uuid4())
        resp: EchoResponse
        try:
            metadata = self.metadata[:]
            metadata.append(('x-request-id', request_id))  # Set a Request ID
            resp = self.crypto_stub.Echo(EchoRequest(message=message), metadata=metadata, timeout=3)
        except Exception as e:
            self.print_stderr(
                f'ERROR: {e.__class__.__name__} Problem encountered sending gRPC message (rqId: {request_id}): {e}'
            )
        else:
            if resp:
                return resp.message
            self.print_stderr(f'ERROR: Problem sending Echo request ({message}) to {self.url}. rqId: {request_id}')
        return None

    def get_dependencies(self, dependencies: json, depth: int = 1) -> dict:
        if not dependencies:
            self.print_stderr('ERROR: No dependency data supplied to submit to the API.')
            return None
        resp = self.get_dependencies_json(dependencies, depth)
        if not resp:
            self.print_stderr(f'ERROR: No response for dependency request: {dependencies}')
        return resp

    def get_dependencies_json(self, dependencies: dict, depth: int = 1) -> dict:
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
        # determine if we are using gRPC or REST based on the use_grpc flag
        process_file = self._process_dep_file_grpc if self.use_grpc else self._process_dep_file_rest
        # Process the dependency files in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_CONCURRENT_REQUESTS) as executor:
            future_to_file = {executor.submit(process_file, file, depth): file for file in files_json}
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

    def _process_dep_file_grpc(self, file, depth: int = 1) -> dict:
        """
        Process a single file using gRPC

        :param file: dependency file purls
        :param depth: depth to search (default: 1)
        :return: response JSON or None
        """
        request_id = str(uuid.uuid4())
        try:
            file_request = {'files': [file]}
            request = ParseDict(file_request, DependencyRequest())
            request.depth = depth
            metadata = self.metadata[:]
            metadata.append(('x-request-id', request_id))
            self.print_debug(f'Sending dependency data via gRPC for decoration (rqId: {request_id})...')
            resp = self.dependencies_stub.GetDependencies(request, metadata=metadata, timeout=self.timeout)
            return MessageToDict(resp, preserving_proto_field_name=True)
        except Exception as e:
            self.print_stderr(
                f'ERROR: {e.__class__.__name__} Problem encountered sending gRPC message (rqId: {request_id}): {e}'
            )
        return None

    def get_vulnerabilities_json(self, purls: dict) -> dict:
        """
        Client function to call the rpc for Vulnerability GetVulnerabilities
        It will either use REST (default) or gRPC depending on the use_grpc flag
        :param purls: Message to send to the service
        :return: Server response or None
        """
        if self.use_grpc:
            return self._get_vulnerabilities_grpc(purls)
        else:
            return self._get_vulnerabilities_rest(purls)

    def _get_vulnerabilities_grpc(self, purls: dict) -> dict:
        """
        Client function to call the rpc for Vulnerability GetVulnerabilities
        :param purls: Message to send to the service
        :return: Server response or None
        """
        if not purls:
            self.print_stderr('ERROR: No message supplied to send to gRPC service.')
            return None
        request_id = str(uuid.uuid4())
        resp: ComponentsVulnerabilityResponse
        try:
            request = ParseDict(purls, ComponentsRequest())  # Parse the JSON/Dict into the purl request object
            metadata = self.metadata[:]
            metadata.append(('x-request-id', request_id))  # Set a Request ID
            self.print_debug(f'Sending vulnerability data for decoration (rqId: {request_id})...')
            resp = self.vuln_stub.GetComponentsVulnerabilities(request, metadata=metadata, timeout=self.timeout)
        except Exception as e:
            self.print_stderr(
                f'ERROR: {e.__class__.__name__} Problem encountered sending gRPC message (rqId: {request_id}): {e}'
            )
        else:
            if resp:
                if not self._check_status_response(resp.status, request_id):
                    return None
                resp_dict = MessageToDict(resp, preserving_proto_field_name=True)  # Convert gRPC response to a dict
                del resp_dict['status']
                return resp_dict
        return None

    def get_semgrep_json(self, purls: dict) -> dict:
        """
        Client function to call the rpc for Semgrep GetIssues
        :param purls: Message to send to the service
        :return: Server response or None
        """
        if not purls:
            self.print_stderr('ERROR: No message supplied to send to gRPC service.')
            return None
        request_id = str(uuid.uuid4())
        resp: SemgrepResponse
        try:
            request = ParseDict(purls, PurlRequest())  # Parse the JSON/Dict into the purl request object
            metadata = self.metadata[:]
            metadata.append(('x-request-id', request_id))  # Set a Request ID
            self.print_debug(f'Sending semgrep data for decoration (rqId: {request_id})...')
            resp = self.semgrep_stub.GetIssues(request, metadata=metadata, timeout=self.timeout)
        except Exception as e:
            self.print_stderr(
                f'ERROR: {e.__class__.__name__} Problem encountered sending gRPC message (rqId: {request_id}): {e}'
            )
        else:
            if resp:
                if not self._check_status_response(resp.status, request_id):
                    return None
                resp_dict = MessageToDict(resp, preserving_proto_field_name=True)  # Convert gRPC response to a dict
                del resp_dict['status']
                return resp_dict
        return None

    def search_components_json(self, search: dict) -> dict:
        """
        Client function to call the rpc for Components SearchComponents
        :param search: Message to send to the service
        :return: Server response or None
        """
        if not search:
            self.print_stderr('ERROR: No message supplied to send to gRPC service.')
            return None
        request_id = str(uuid.uuid4())
        resp: CompSearchResponse
        try:
            request = ParseDict(search, CompSearchRequest())  # Parse the JSON/Dict into the purl request object
            metadata = self.metadata[:]
            metadata.append(('x-request-id', request_id))  # Set a Request ID
            self.print_debug(f'Sending component search data (rqId: {request_id})...')
            resp = self.comp_search_stub.SearchComponents(request, metadata=metadata, timeout=self.timeout)
        except Exception as e:
            self.print_stderr(
                f'ERROR: {e.__class__.__name__} Problem encountered sending gRPC message (rqId: {request_id}): {e}'
            )
        else:
            if resp:
                if not self._check_status_response(resp.status, request_id):
                    return None
                resp_dict = MessageToDict(resp, preserving_proto_field_name=True)  # Convert gRPC response to a dict
                del resp_dict['status']
                return resp_dict
        return None

    def get_component_versions_json(self, search: dict) -> dict:
        """
        Client function to call the rpc for Components GetComponentVersions
        :param search: Message to send to the service
        :return: Server response or None
        """
        if not search:
            self.print_stderr('ERROR: No message supplied to send to gRPC service.')
            return None
        request_id = str(uuid.uuid4())
        resp: CompVersionResponse
        try:
            request = ParseDict(search, CompVersionRequest())  # Parse the JSON/Dict into the purl request object
            metadata = self.metadata[:]
            metadata.append(('x-request-id', request_id))  # Set a Request ID
            self.print_debug(f'Sending component version data (rqId: {request_id})...')
            resp = self.comp_search_stub.GetComponentVersions(request, metadata=metadata, timeout=self.timeout)
        except Exception as e:
            self.print_stderr(
                f'ERROR: {e.__class__.__name__} Problem encountered sending gRPC message (rqId: {request_id}): {e}'
            )
        else:
            if resp:
                if not self._check_status_response(resp.status, request_id):
                    return None
                resp_dict = MessageToDict(resp, preserving_proto_field_name=True)  # Convert gRPC response to a dict
                del resp_dict['status']
                return resp_dict
        return None

    def folder_hash_scan(self, request: Dict) -> Optional[Dict]:
        """
        Client function to call the rpc for Folder Hashing Scan

        Args:
            request (Dict): Folder Hash Request

        Returns:
            Optional[Dict]: Folder Hash Response, or None if the request was not succesfull
        """
        return self._call_rpc(
            self.scanning_stub.FolderHashScan,
            request,
            HFHRequest,
            'Sending folder hash scan data (rqId: {rqId})...',
        )

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
        self.print_debug(debug_msg.format(rqId=request_id))
        try:
            resp = rpc_method(request_obj, metadata=metadata, timeout=self.timeout)
        except grpc.RpcError as e:
            raise ScanossGrpcError(
                f'{e.__class__.__name__} while sending gRPC message (rqId: {request_id}): {e.details()}'
            )
        if resp and not self._check_status_response(resp.status, request_id):
            return None

        resp_dict = MessageToDict(resp, preserving_proto_field_name=True)
        return resp_dict

    def _check_status_response(self, status_response: StatusResponse, request_id: str = None) -> bool:
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
            if status_code == ScanossGrpcStatusCode.SUCCESS_WITH_WARNINGS:
                msg = 'Succeeded with warnings'
                ret_val = True  # No need to fail as it succeeded with warnings
            elif status_code == ScanossGrpcStatusCode.FAILED_WITH_WARNINGS:
                msg = 'Failed with warnings'
            self.print_stderr(f'{msg} (rqId: {request_id} - status: {status_code}): {status_response.message}')
            return ret_val
        return True

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

    def get_provenance_json(self, purls: dict) -> dict:
        """
        Client function to call the rpc for GetComponentProvenance
        :param purls: Message to send to the service
        :return: Server response or None
        """
        if not purls:
            self.print_stderr('ERROR: No message supplied to send to gRPC service.')
            return None
        request_id = str(uuid.uuid4())
        resp: ContributorResponse
        try:
            request = ParseDict(purls, PurlRequest())  # Parse the JSON/Dict into the purl request object
            metadata = self.metadata[:]
            metadata.append(('x-request-id', request_id))  # Set a Request ID
            self.print_debug(f'Sending data for provenance decoration (rqId: {request_id})...')
            resp = self.provenance_stub.GetComponentContributors(request, metadata=metadata, timeout=self.timeout)
        except Exception as e:
            self.print_stderr(
                f'ERROR: {e.__class__.__name__} Problem encountered sending gRPC message (rqId: {request_id}): {e}'
            )
        else:
            if resp:
                if not self._check_status_response(resp.status, request_id):
                    return None
                resp_dict = MessageToDict(resp, preserving_proto_field_name=True)  # Convert gRPC response to a dict
                return resp_dict
        return None

    def get_provenance_origin(self, request: Dict) -> Optional[Dict]:
        """
        Client function to call the rpc for GetComponentOrigin

        Args:
            request (Dict): GetComponentOrigin Request

        Returns:
            Optional[Dict]: OriginResponse, or None if the request was not successfull
        """
        return self._call_rpc(
            self.provenance_stub.GetComponentOrigin,
            request,
            PurlRequest,
            'Sending data for provenance origin decoration (rqId: {rqId})...',
        )

    def get_crypto_algorithms_for_purl(self, request: Dict) -> Optional[Dict]:
        """
        Client function to call the rpc for GetAlgorithms for a list of purls

        Args:
            request (Dict): PurlRequest

        Returns:
            Optional[Dict]: AlgorithmResponse, or None if the request was not successfull
        """
        return self._call_rpc(
            self.crypto_stub.GetAlgorithms,
            request,
            PurlRequest,
            'Sending data for cryptographic algorithms decoration (rqId: {rqId})...',
        )

    def get_crypto_algorithms_in_range_for_purl(self, request: Dict) -> Optional[Dict]:
        """
        Client function to call the rpc for GetAlgorithmsInRange for a list of purls

        Args:
            request (Dict): PurlRequest

        Returns:
            Optional[Dict]: AlgorithmsInRangeResponse, or None if the request was not successfull
        """
        return self._call_rpc(
            self.crypto_stub.GetAlgorithmsInRange,
            request,
            PurlRequest,
            'Sending data for cryptographic algorithms in range decoration (rqId: {rqId})...',
        )

    def get_encryption_hints_for_purl(self, request: Dict) -> Optional[Dict]:
        """
        Client function to call the rpc for GetEncryptionHints for a list of purls

        Args:
            request (Dict): PurlRequest

        Returns:
            Optional[Dict]: HintsResponse, or None if the request was not successfull
        """
        return self._call_rpc(
            self.crypto_stub.GetEncryptionHints,
            request,
            PurlRequest,
            'Sending data for encryption hints decoration (rqId: {rqId})...',
        )

    def get_encryption_hints_in_range_for_purl(self, request: Dict) -> Optional[Dict]:
        """
        Client function to call the rpc for GetHintsInRange for a list of purls

        Args:
            request (Dict): PurlRequest

        Returns:
            Optional[Dict]: HintsInRangeResponse, or None if the request was not successfull
        """
        return self._call_rpc(
            self.crypto_stub.GetHintsInRange,
            request,
            PurlRequest,
            'Sending data for encryption hints in range decoration (rqId: {rqId})...',
        )

    def get_versions_in_range_for_purl(self, request: Dict) -> Optional[Dict]:
        """
        Client function to call the rpc for GetVersionsInRange for a list of purls

        Args:
            request (Dict): PurlRequest

        Returns:
            Optional[Dict]: VersionsInRangeResponse, or None if the request was not successfull
        """
        return self._call_rpc(
            self.crypto_stub.GetVersionsInRange,
            request,
            PurlRequest,
            'Sending data for cryptographic versions in range decoration (rqId: {rqId})...',
        )

    def load_generic_headers(self):
        """
        Adds custom headers from req_headers to metadata.

        If x-api-key is present and no URL is configured (directly or via
        environment), sets URL to the premium endpoint (DEFAULT_URL2).
        """
        if self.req_headers:  # Load generic headers
            for key, value in self.req_headers.items():
                if key == 'x-api-key':  # Set premium URL if x-api-key header is set
                    if not self.url and not os.environ.get('SCANOSS_GRPC_URL'):
                        self.url = DEFAULT_URL2  # API key specific and no alternative URL, so use the default premium
                    self.api_key = value
                self.metadata.append((key, value))
                self.headers[key] = value

    #
    # End of gRPC Client Functions
    #
    # Start of REST Client Functions
    #

    def rest_post(self, uri: str, request_id: str, data: dict) -> dict:
        """
        Post the specified data to the given URI.
        :param request_id: request id
        :param uri: URI to post to
        :param data: json data to post
        :return: JSON response or None
        """
        if not uri:
            self.print_stderr('Error: Missing URI. Cannot search for project.')
            return None
        self.print_trace(f'Sending REST POST data to {uri}...')
        headers = self.headers
        headers['x-request-id'] = request_id  # send a unique request id for each post
        retry = 0  # Add some retry logic to cater for timeouts, etc.
        while retry <= self.retry_limit:
            retry += 1
            try:
                response = self.session.post(uri, headers=headers, json=data, timeout=self.timeout)
                response.raise_for_status()  # Raises an HTTPError for bad responses
                return response.json()
            except requests.exceptions.RequestException as e:
                self.print_stderr(f'Error: Problem posting data to {uri}: {e}')
            except (requests.exceptions.SSLError, requests.exceptions.ProxyError) as e:
                self.print_stderr(f'ERROR: Exception ({e.__class__.__name__}) POSTing data - {e}.')
                raise Exception(f'ERROR: The SCANOSS Decoration API request failed for {uri}') from e
            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
                if retry > self.retry_limit:  # Timed out retry_limit or more times, fail
                    self.print_stderr(f'ERROR: {e.__class__.__name__} POSTing decoration data ({request_id}): {e}')
                    raise Exception(
                        f'ERROR: The SCANOSS Decoration API request timed out ({e.__class__.__name__}) for {uri}'
                    ) from e
                else:
                    self.print_stderr(f'Warning: {e.__class__.__name__} communicating with {self.url}. Retrying...')
                    time.sleep(5)
            except Exception as e:
                self.print_stderr(
                    f'ERROR: Exception ({e.__class__.__name__}) POSTing data ({request_id}) to {uri}: {e}'
                )
                raise Exception(f'ERROR: The SCANOSS Decoration API request failed for {uri}') from e
        return None

    def _get_vulnerabilities_rest(self, purls: dict):
        """
        Get the vulnerabilities for the given purls using REST API
        :param purls: Purl Request dictionary
        :return: Vulnerability Response, or None if the request was unsuccessful
        """
        if not purls:
            self.print_stderr('ERROR: No message supplied to send to REST decoration service.')
            return None
        request_id = str(uuid.uuid4())
        self.print_debug(f'Sending data for Vulnerabilities via REST (request id: {request_id})...')
        response = self.rest_post(f'{self.orig_url}{DEFAULT_URI_PREFIX}/vulnerabilities/components', request_id, purls)
        self.print_trace(f'Received response for Vulnerabilities via REST (request id: {request_id}): {response}')
        if response:
            # Parse the JSON/Dict into the purl response
            resp_obj = ParseDict(response, ComponentsVulnerabilityResponse(), True)
            if resp_obj:
                self.print_debug(f'Vulnerability Response: {resp_obj}')
                if not self._check_status_response(resp_obj.status, request_id):
                    return None
            del response['status']
            return response
        return None

    def _process_dep_file_rest(self, file, depth: int = 1) -> dict:
        """
        Porcess a single dependency file using REST

        :param file: dependency file purls
        :param depth: depth to search (default: 1)
        :return: response JSON or None
        """
        request_id = str(uuid.uuid4())
        self.print_debug(f'Sending data for Dependencies via REST (request id: {request_id})...')
        file_request = {'files': [file], 'depth': depth}
        response = self.rest_post(f'{self.orig_url}{DEFAULT_URI_PREFIX}/dependencies/dependencies', request_id, file_request)
        self.print_trace(f'Received response for Dependencies via REST (request id: {request_id}): {response}')
        if response:
            return response
        return None
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