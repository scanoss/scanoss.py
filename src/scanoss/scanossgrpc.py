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
import logging
import grpc
import json

from .api.dependencies.v2.scanoss_dependencies_pb2_grpc import DependenciesStub
from .api.dependencies.v2.scanoss_dependencies_pb2 import DependencyRequest, DependencyResponse
from .api.common.v2.scanoss_common_pb2 import EchoRequest, EchoResponse, Status, StatusCode
from .scanossbase import ScanossBase

# DEFAULT_URL      = "https://osskb.org/api/scan/direct"
DEFAULT_URL = "localhost:50051"
SCANOSS_GRPC_URL = os.environ.get("SCANOSS_GRPC_URL") if os.environ.get("SCANOSS_GRPC_URL") else DEFAULT_URL


class ScanossGrpc(ScanossBase):
    """
    Client for gRPC functionality
    """

    def __init__(self, url: str = None, debug: bool = False, trace: bool = False, quiet: bool = False):
        """

        :param url:
        :param debug:
        :param trace:
        :param quiet:
        """
        self.debug = debug
        self.quiet = quiet
        self.trace = trace
        self.url = url if url else SCANOSS_GRPC_URL
        self.dependencies_stub = DependenciesStub(grpc.insecure_channel(self.url))

    def deps_echo(self, message: str = 'Hello there!') -> str:
        """
        Send Echo message to the Dependency service
        :param message: Message to send (default: Hello there!)
        :return: echo or None
        """
        resp: EchoResponse
        try:
            resp = self.dependencies_stub.Echo(EchoRequest(message=message))
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
        resp = self.get_dependencies_str(json.dumps(dependencies), depth)
        data = None
        if resp:
            try:
                data = json.loads(resp)
            except Exception as e:
                print(f'ERROR: Problem parsing dependency response JSON: {e} - {resp}')
        return data

    def get_dependencies_str(self, dependencies: str, depth: int = 1) -> str:
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
            resp = self.dependencies_stub.GetDependencies(DependencyRequest(dependencies=dependencies, depth=depth))
        except Exception as e:
            self.print_stderr(f'ERROR: Problem encountered sending gRPC message: {e}')
        else:
            if resp:
                if not self._check_status_response(resp.status):
                    return None
            return resp.dependencies
        return None

    def _check_status_response(self, status_response: Status) -> bool:
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

