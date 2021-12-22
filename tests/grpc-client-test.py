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
import unittest
import json

from scanoss.scancodedeps import ScancodeDeps
from scanoss.scanossgrpc import ScanossGrpc


class MyTestCase(unittest.TestCase):
    """
    Unit test cases for GRPC comms
    """

    def test_grpc_dep_echo(self):
        """

        :return:
        """
        grpc_client = ScanossGrpc(debug=True, url='localhost:50051')
        echo_resp = grpc_client.deps_echo('testing dep echo')
        self.assertIsNotNone(echo_resp)

    def test_grpc_connection(self):
        """
        ?
        """
        sc_deps = ScancodeDeps(debug=True)
        dep_file = "data/scancode-deps.json"
        deps = sc_deps.produce_from_file(dep_file)
        print(f'Dependency JSON: {deps}')
        self.assertIsNotNone(deps)
        grpc_client = ScanossGrpc(debug=True, url='localhost:50051')
        resp = grpc_client.get_dependencies(deps)
        self.assertIsNotNone(resp)
        print(f'Resp: {resp}')
        # data = None
        # try:
        #     data = json.loads(resp.message)
        # except Exception as e:
        #     print(f'ERROR: Problem parsing input JSON: {e}')
        # self.assertIsNotNone(data)
        # print(f'Dep Resp: {data}')

