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

from scanoss.scancodedeps import ScancodeDeps
from scanoss.scanossgrpc import ScanossGrpc
from scanoss.threadeddependencies import ThreadedDependencies


class MyTestCase(unittest.TestCase):
    """
    Unit test cases for Scancode Dependency analysis
    """
    TEST_LOCAL = os.getenv("SCANOSS_TEST_LOCAL", 'True').lower() in ('true', '1', 't', 'yes', 'y')

    def test_deps_parse(self):
        """
        Parse the saved scancode dependency data file
        """
        sc_deps = ScancodeDeps(debug=True)
        dep_file = "data/scancode-deps.json"
        deps = sc_deps.produce_from_file(dep_file)
        print(f'Dependency JSON: {deps}')
        self.assertIsNotNone(deps)

    def test_scan_dir(self):
        """
        Run a dependency scan of the current directory, then parse those results
        """
        sc_deps = ScancodeDeps(debug=True)

        self.assertTrue(sc_deps.run_scan(what_to_scan="."))
        deps = sc_deps.produce_from_file()
        sc_deps.remove_interim_file()
        print(f'Dependency JSON: {deps}')
        self.assertIsNotNone(deps)

    def test_threaded_scan_dir(self):
        """
        Run a dependency scan of the current directory, then parse those results
        """
        # with open('scanoss-com.pem', 'rb') as f:
        #     root_certs = f.read()
        if MyTestCase.TEST_LOCAL:
            server_type = "local"
            grpc_client = ScanossGrpc(debug=True, url='localhost:50051')
        else:
            server_type = "remote"
            grpc_client = ScanossGrpc(debug=True)
        sc_deps = ScancodeDeps(debug=True)
        threaded_deps = ThreadedDependencies(sc_deps, grpc_client, ".", debug=True, trace=True)
        self.assertTrue(threaded_deps.run(what_to_scan=".", wait=True))
        deps = threaded_deps.responses
        print(f'Dependency results ({server_type}): {deps}')
        self.assertIsNotNone(deps)


if __name__ == '__main__':
    unittest.main()
