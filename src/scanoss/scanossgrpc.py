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

import json
import os
import uuid
from dataclasses import dataclass
from typing import Dict, Optional
from urllib.parse import urlparse

import grpc
from google.protobuf.json_format import MessageToDict, ParseDict
from pypac.parser import PACFile
from pypac.resolver import ProxyResolver

from scanoss.api.scanning.v2.scanoss_scanning_pb2_grpc import ScanningStub
from scanoss.constants import DEFAULT_TIMEOUT

from . import __version__
from .api.common.v2.scanoss_common_pb2 import (
    EchoRequest,
    EchoResponse,
    PurlRequest,
    StatusCode,
    StatusResponse,
)
from .api.components.v2.scanoss_components_pb2 import (
    CompSearchRequest,
    CompSearchResponse,
    CompVersionRequest,
    CompVersionResponse,
)
from .api.components.v2.scanoss_components_pb2_grpc import ComponentsStub
from .api.cryptography.v2.scanoss_cryptography_pb2 import AlgorithmResponse
from .api.cryptography.v2.scanoss_cryptography_pb2_grpc import CryptographyStub
from .api.dependencies.v2.scanoss_dependencies_pb2 import (
    DependencyRequest,
    DependencyResponse,
)
from .api.dependencies.v2.scanoss_dependencies_pb2_grpc import DependenciesStub
from .api.scanning.v2.scanoss_scanning_pb2 import HFHRequest
from .api.semgrep.v2.scanoss_semgrep_pb2 import SemgrepResponse
from .api.semgrep.v2.scanoss_semgrep_pb2_grpc import SemgrepStub
from .api.vulnerabilities.v2.scanoss_vulnerabilities_pb2 import VulnerabilityResponse
from .api.vulnerabilities.v2.scanoss_vulnerabilities_pb2_grpc import VulnerabilitiesStub
from .scanossbase import ScanossBase

DEFAULT_URL = 'https://api.osskb.org'  # default free service URL
DEFAULT_URL2 = 'https://api.scanoss.com'  # default premium service URL
SCANOSS_GRPC_URL = os.environ.get('SCANOSS_GRPC_URL') if os.environ.get('SCANOSS_GRPC_URL') else DEFAULT_URL
SCANOSS_API_KEY = os.environ.get('SCANOSS_API_KEY') if os.environ.get('SCANOSS_API_KEY') else ''


class ScanossGrpc(ScanossBase):
    """
    Client for gRPC functionality
    """

    def __init__(  # noqa: PLR0913
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
        self.url = url if url else SCANOSS_GRPC_URL
        self.api_key = api_key if api_key else SCANOSS_API_KEY
        if self.api_key and not url and not os.environ.get('SCANOSS_GRPC_URL'):
            self.url = DEFAULT_URL2  # API key specific and no alternative URL, so use the default premium
        self.url = self.url.lower()
        self.orig_url = self.url  # Used for proxy lookup
        self.timeout = timeout
        self.proxy = proxy
        self.grpc_proxy = grpc_proxy
        self.pac = pac
        self.metadata = []
        if self.api_key:
            self.metadata.append(('x-api-key', api_key))  # Set API key if we have one
        if ver_details:
            self.metadata.append(('x-scanoss-client', ver_details))
        self.metadata.append(('user-agent', f'scanoss-py/{__version__}'))
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
        if secure is False:  # insecure connection
            self.comp_search_stub = ComponentsStub(grpc.insecure_channel(self.url))
            self.crypto_stub = CryptographyStub(grpc.insecure_channel(self.url))
            self.dependencies_stub = DependenciesStub(grpc.insecure_channel(self.url))
            self.semgrep_stub = SemgrepStub(grpc.insecure_channel(self.url))
            self.vuln_stub = VulnerabilitiesStub(grpc.insecure_channel(self.url))
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
            # self.print_stderr(f'resp: {resp} - call: {call}')
            # response_id = ""
            # if not call:
            #     self.print_stderr(f'No call to leverage.')
            # for key, value in call.trailing_metadata():
            #     print('Greeter client received trailing metadata: key=%s value=%s' % (key, value))
            #
            # for key, value in call.trailing_metadata():
            #     if key == 'x-response-id':
            #         response_id = value
            # self.print_stderr(f'Response ID: {response_id}. Metadata: {call.trailing_metadata()}')
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
        request_id = str(uuid.uuid4())
        resp: DependencyResponse
        try:
            files_json = dependencies.get('files')
            if files_json is None or len(files_json) == 0:
                self.print_stderr('ERROR: No dependency data supplied to send to gRPC service.')
                return None
            request = ParseDict(dependencies, DependencyRequest())  # Parse the JSON/Dict into the dependency object
            request.depth = depth
            metadata = self.metadata[:]
            metadata.append(('x-request-id', request_id))  # Set a Request ID
            self.print_debug(f'Sending dependency data for decoration (rqId: {request_id})...')
            resp = self.dependencies_stub.GetDependencies(request, metadata=metadata, timeout=self.timeout)
        except Exception as e:
            self.print_stderr(
                f'ERROR: {e.__class__.__name__} Problem encountered sending gRPC message (rqId: {request_id}): {e}'
            )
        else:
            if resp:
                if not self._check_status_response(resp.status, request_id):
                    return None
                return MessageToDict(resp, preserving_proto_field_name=True)  # Convert gRPC response to a dictionary
        return None

    def get_crypto_json(self, purls: dict) -> dict:
        """
        Client function to call the rpc for Cryptography GetAlgorithms
        :param purls: Message to send to the service
        :return: Server response or None
        """
        if not purls:
            self.print_stderr('ERROR: No message supplied to send to gRPC service.')
            return None
        request_id = str(uuid.uuid4())
        resp: AlgorithmResponse
        try:
            request = ParseDict(purls, PurlRequest())  # Parse the JSON/Dict into the purl request object
            metadata = self.metadata[:]
            metadata.append(('x-request-id', request_id))  # Set a Request ID
            self.print_debug(f'Sending crypto data for decoration (rqId: {request_id})...')
            resp = self.crypto_stub.GetAlgorithms(request, metadata=metadata, timeout=self.timeout)
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

    def get_vulnerabilities_json(self, purls: dict) -> dict:
        """
        Client function to call the rpc for Vulnerability GetVulnerabilities
        :param purls: Message to send to the service
        :return: Server response or None
        """
        if not purls:
            self.print_stderr('ERROR: No message supplied to send to gRPC service.')
            return None
        request_id = str(uuid.uuid4())
        resp: VulnerabilityResponse
        try:
            request = ParseDict(purls, PurlRequest())  # Parse the JSON/Dict into the purl request object
            metadata = self.metadata[:]
            metadata.append(('x-request-id', request_id))  # Set a Request ID
            self.print_debug(f'Sending crypto data for decoration (rqId: {request_id})...')
            resp = self.vuln_stub.GetVulnerabilities(request, metadata=metadata, timeout=self.timeout)
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

    def folder_hash_scan(self, request: Dict) -> Dict:
        """
        Client function to call the rpc for Folder Hashing Scan

        Args:
            request (Dict): Folder Hash Request

        Returns:
            Dict: Folder Hash Response
        """
        return self._call_rpc(
            self.scanning_stub.FolderHashScan,
            request,
            HFHRequest,
            'Sending folder hash scan data (rqId: {rqId})...',
        )

    def _call_rpc(self, rpc_method, request_input, request_type, debug_msg: Optional[str] = None) -> dict:
        """
        Call a gRPC method and return the response as a dictionary

        Args:
            rpc_method (): The gRPC stub method
            request_input (): Either a dict or a gRPC request object.
            request_type (): The type of the gRPC request object.
            debug_msg (str, optional): Debug message template that can include {rqId} placeholder.

        Returns:
            dict: The parsed gRPC response as a dictionary, or None if an error occurred.
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
            self.print_stderr(
                f'ERROR: {e.__class__.__name__} while sending gRPC message (rqId: {request_id}): {e.details()}'
            )
            return None

        if resp and not self._check_status_response(resp.status, request_id):
            return None

        resp_dict = MessageToDict(resp, preserving_proto_field_name=True)
        resp_dict.pop('status', None)
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
        if status_code > 1:
            msg = 'Unsuccessful'
            if status_code == 2:  # noqa: PLR2004
                msg = 'Succeeded with warnings'
            elif status_code == 3:  # noqa: PLR2004
                msg = 'Failed with warnings'
            self.print_stderr(f'{msg} (rqId: {request_id} - status: {status_code}): {status_response.message}')
            return False
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
    pac: Optional[PACFile] = None
    timeout: Optional[int] = DEFAULT_TIMEOUT
    proxy: Optional[str] = None
    grpc_proxy: Optional[str] = None


def create_grpc_config_from_args(args) -> GrpcConfig:
    return GrpcConfig(
        url=getattr(args, 'url', DEFAULT_URL),
        api_key=getattr(args, 'api_key', SCANOSS_API_KEY),
        debug=getattr(args, 'debug', False),
        trace=getattr(args, 'trace', False),
        quiet=getattr(args, 'quiet', False),
        ver_details=getattr(args, 'ver_details', None),
        ca_cert=getattr(args, 'ca_cert', None),
        pac=getattr(args, 'pac', None),
        timeout=getattr(args, 'timeout', DEFAULT_TIMEOUT),
        proxy=getattr(args, 'proxy', None),
        grpc_proxy=getattr(args, 'grpc_proxy', None),
    )
