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

import os
import grpc
import json
from urllib.parse import urlparse
from google.protobuf.json_format import MessageToDict, ParseDict

from .api.dependencies.v2.scanoss_dependencies_pb2_grpc import DependenciesStub
from .api.dependencies.v2.scanoss_dependencies_pb2 import DependencyRequest, DependencyResponse
from .api.common.v2.scanoss_common_pb2 import EchoRequest, EchoResponse, StatusResponse, StatusCode
from .scanossbase import ScanossBase

# DEFAULT_URL      = "https://osskb.org"
# DEFAULT_URL = "localhost:50051"
DEFAULT_URL = "https://scanoss.com"
SCANOSS_GRPC_URL = os.environ.get("SCANOSS_GRPC_URL") if os.environ.get("SCANOSS_GRPC_URL") else DEFAULT_URL
SCANOSS_API_KEY = os.environ.get("SCANOSS_API_KEY") if os.environ.get("SCANOSS_API_KEY") else ''


class ScanossGrpc(ScanossBase):
    """
    Client for gRPC functionality
    """

    def __init__(self, url: str = None, debug: bool = False, trace: bool = False, quiet: bool = False,
                 cert: bytes = None, api_key: str = None, ver_details: str = None):
        """

        :param url:
        :param debug:
        :param trace:
        :param quiet:
        :param cert:
        """
        super().__init__(debug, trace, quiet)
        self.url = url if url else SCANOSS_GRPC_URL
        self.url = self.url.lower()
        self.api_key = api_key if api_key else SCANOSS_API_KEY
        self.metadata = []
        if self.api_key:
            self.metadata.append(('x-api-key', api_key))  # Set API key if we have one
        if ver_details:
            self.metadata.append(('x-scanoss-client', ver_details))
        secure = True if self.url.startswith('https:') else False  # Is it a secure connection?
        if self.url.startswith('http'):
            u = urlparse(self.url)
            port = u.port
            if port is None:
                port = 443 if u.scheme == 'https' else 80  # Set the default port number if it's not available
            self.url = f'{u.hostname}:{port}'
        if cert is not None:
            secure = True
        self.print_debug(f'Setting up (secure: {secure}) connection to {self.url}...')
        if secure is False:
            self.dependencies_stub = DependenciesStub(grpc.insecure_channel(self.url))  # insecure connection
        else:
            if cert is not None:
                credentials = grpc.ssl_channel_credentials(cert)  # secure with specified certificate
            else:
                credentials = grpc.ssl_channel_credentials()      # secure connection with default certificate
            self.dependencies_stub = DependenciesStub(grpc.secure_channel(self.url, credentials))

    def deps_echo(self, message: str = 'Hello there!') -> str:
        """
        Send Echo message to the Dependency service
        :param message: Message to send (default: Hello there!)
        :return: echo or None
        """
        resp: EchoResponse
        try:
            resp = self.dependencies_stub.Echo(EchoRequest(message=message), metadata=self.metadata)
        except Exception as e:
            self.print_stderr(f'ERROR: Problem encountered sending gRPC message: {e}')
        else:
            if resp:
                return resp.message
            self.print_stderr(f'ERROR: Problem sending Echo request ({message}) to {self.url}')
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
            self.print_stderr(f'ERROR: No message supplied to send to gRPC service.')
            return None
        resp: DependencyResponse
        try:
            files_json = dependencies.get("files")
            if files_json is None or len(files_json) == 0:
                self.print_stderr(f'ERROR: No dependency data supplied to send to gRPC service.')
                return None
            request = ParseDict(dependencies, DependencyRequest())  # Parse the JSON/Dict into the dependency object
            request.depth = depth
            resp = self.dependencies_stub.GetDependencies(request, metadata=self.metadata)
        except Exception as e:
            self.print_stderr(f'ERROR: Problem encountered sending gRPC message: {e}')
        else:
            if resp:
                if not self._check_status_response(resp.status):
                    return None
                return MessageToDict(resp, preserving_proto_field_name=True)  # Convert the gRPC response to a dictionary
        return None

    def get_dependencies_str(self, dependencies: str, depth: int = 1) -> str:  # TODO remove?
        """
        Client function to call the rpc for GetDependencies
        :param dependencies: Message to send to the service
        :param depth: depth of sub-dependencies to search (default: 1)
        :return: Server response or None
        """
        if not dependencies:
            self.print_stderr(f'ERROR: No message supplied to send to gRPC service.')
            return None
        resp: DependencyResponse
        try:
            purl = DependencyRequest.Purls(purl="pkg", requirement="^1.0")
            purls = [purl]
            dep_req = DependencyRequest.Files(file="package.json", purls=purls)
            files = [dep_req]
            resp = self.dependencies_stub.GetDependencies(DependencyRequest(files=files, depth=depth), metadata=self.metadata)
        except Exception as e:
            self.print_stderr(f'ERROR: Problem encountered sending gRPC message: {e}')
        else:
            if resp:
                if not self._check_status_response(resp.status):
                    return None
            return resp.dependencies
        return None

    def _check_status_response(self, status_response: StatusResponse) -> bool:
        """
        Check the response object to see if the command was successful or not
        :param status_response: Status Response
        :return: True if successful, False otherwise
        """
        if not status_response:
            self.print_stderr('Warning: No status response supplied. Assuming it was ok.')
            return True
        self.print_debug(f'Checking response status: {status_response}')
        status_code: StatusCode = status_response.status
        # self.print_stderr(f'Status Code: {status_code}, Message: {status_response.message}')
        if status_code > 1:
            self.print_stderr(f'Not such a success: {status_response.message}')
            return False
        return True
#
# End of ScanossGrpc Class
#
