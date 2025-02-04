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
import unittest
from math import trunc

from scanoss.components import Components
from scanoss.scancodedeps import ScancodeDeps
from scanoss.scanossgrpc import ScanossGrpc


class MyTestCase(unittest.TestCase):
    """
    Unit test cases for GRPC comms
    """

    TEST_LOCAL = os.getenv('SCANOSS_TEST_LOCAL', 'True').lower() in ('true', '1', 't', 'yes', 'y')

    def test_grpc_dep_echo(self):
        """
        Test the basic echo rpc call on the local server
        """
        if MyTestCase.TEST_LOCAL:
            server_type = 'local'
            grpc_client = ScanossGrpc(debug=True, url='localhost:50051')
        else:
            server_type = 'remote'
            grpc_client = ScanossGrpc(debug=True)
        echo_resp = grpc_client.deps_echo(f'testing dep echo ({server_type})')
        print(f'Echo Resp ({server_type}): {echo_resp}')
        self.assertIsNotNone(echo_resp)

    def test_grpc_get_dependencies(self):
        """
        Test getting dependencies from the local gRPC server
        """
        sc_deps = ScancodeDeps(debug=True)
        dep_file = 'data/scancode-deps.json'
        deps = sc_deps.produce_from_file(dep_file)
        print(f'Dependency JSON: {deps}')
        self.assertIsNotNone(deps)
        if MyTestCase.TEST_LOCAL:
            server_type = 'local'
            grpc_client = ScanossGrpc(debug=True, url='localhost:50051')
        else:
            server_type = 'remote'
            grpc_client = ScanossGrpc(debug=True)
        resp = grpc_client.get_dependencies(deps)
        print(f'Resp ({server_type}): {resp}')
        self.assertIsNotNone(resp)

        dep_files = resp.get('files')
        if dep_files and len(dep_files) > 0:
            for dep_file in dep_files:
                file = dep_file.pop('file', None)
                print(f'File: {file} - {dep_file}')

    def test_load_purls_array(self):
        comps = Components(debug=True, trace=True)
        # Expected value as a dictionary, not a string
        expected_value = {
            'purls': [
                {'purl': 'pkg:github/unoconv/unoconv'},
                {'purl': 'pkg:github/torvalds/linux@v5.13'}
            ]
        }
        components = comps.load_purls(purls=["pkg:github/unoconv/unoconv", "pkg:github/torvalds/linux@v5.13"])
        print(components)
        self.assertEqual(components,expected_value)

if __name__ == '__main__':
    unittest.main()
