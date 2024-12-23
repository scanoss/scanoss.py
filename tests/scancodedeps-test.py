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
import tempfile
import unittest

from scanoss.scancodedeps import ScancodeDeps
from scanoss.scanossgrpc import ScanossGrpc
from scanoss.threadeddependencies import SCOPE, ThreadedDependencies


class MyTestCase(unittest.TestCase):
    """
    Unit test cases for Scancode Dependency analysis
    """

    TEST_LOCAL = os.getenv('SCANOSS_TEST_LOCAL', 'False').lower() in ('true', '1', 't', 'yes', 'y')

    def test_deps_parse(self):
        """
        Parse the saved scancode dependency data file
        """
        sc_deps = ScancodeDeps(debug=True)
        dep_file = 'data/scancode-deps.json'
        deps = sc_deps.produce_from_file(dep_file)
        print(f'Dependency JSON: {deps}')
        self.assertIsNotNone(deps)

    def test_scan_dir(self):
        """
        Run a dependency scan of the current directory, then parse those results
        """
        sc_deps = ScancodeDeps(debug=True)

        self.assertTrue(sc_deps.run_scan(what_to_scan='.'))
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
            server_type = 'local'
            grpc_client = ScanossGrpc(debug=True, url='localhost:50051')
        else:
            server_type = 'remote'
            grpc_client = ScanossGrpc(debug=True)
        sc_deps = ScancodeDeps(debug=True)
        threaded_deps = ThreadedDependencies(sc_deps, grpc_client, '.', debug=True, trace=True)
        self.assertTrue(threaded_deps.run(what_to_scan='.', wait=True))
        deps = threaded_deps.responses
        print(f'Dependency results ({server_type}): {deps}')
        self.assertIsNotNone(deps)

    def test_dep_scope_all(self):
        """
        Run a dependency scan of the current directory, then parse those results
        """
        # with open('scanoss-com.pem', 'rb') as f:
        #     root_certs = f.read()
        if MyTestCase.TEST_LOCAL:
            server_type = 'local'
            grpc_client = ScanossGrpc(debug=True, url='localhost:50051')
        else:
            server_type = 'remote'
            grpc_client = ScanossGrpc(debug=True)
        sc_deps = ScancodeDeps(debug=True)
        threaded_deps = ThreadedDependencies(sc_deps, grpc_client, '.', debug=True, trace=True)
        self.assertTrue(threaded_deps.run(what_to_scan='.', wait=True))
        deps = threaded_deps.responses
        files = deps.get('files')
        package_json_deps = files[0]['dependencies']
        requirements_txt_deps = files[1].get('dependencies', [])
        print(f'Dependency results for: ({files[0]["file"]}), dependencies: {package_json_deps}')
        print(f'Dependency results for: ({files[1]["file"]}), dependencies: {requirements_txt_deps}')
        self.assertEqual(len(package_json_deps), 3)
        self.assertEqual(len(requirements_txt_deps), 6)

    def test_dep_scope_development(self):
        """
        Run a dependency scan of the current directory, then parse those results
        """
        # with open('scanoss-com.pem', 'rb') as f:
        #     root_certs = f.read()
        if MyTestCase.TEST_LOCAL:
            server_type = 'local'
            grpc_client = ScanossGrpc(debug=True, url='localhost:50051')
        else:
            server_type = 'remote'
            grpc_client = ScanossGrpc(debug=True)
        sc_deps = ScancodeDeps(debug=True)
        threaded_deps = ThreadedDependencies(sc_deps, grpc_client, '.', debug=True, trace=True)
        self.assertTrue(threaded_deps.run(what_to_scan='.', wait=True, dep_scope=SCOPE.DEVELOPMENT))
        deps = threaded_deps.responses
        files = deps.get('files')
        package_json_dev_deps = files[0]['dependencies']
        requirements_txt_dev_deps = files[1].get('dependencies', [])
        print(f'Dependency results for: ({files[0]["file"]}), dependencies: {package_json_dev_deps}')
        print(f'Dependency results for: ({files[1]["file"]}), dependencies: {requirements_txt_dev_deps}')
        self.assertNotEquals(len(package_json_dev_deps), len(requirements_txt_dev_deps))
        self.assertEqual(len(package_json_dev_deps), 1)
        # devDependencies of package.json file: "@babel/core": ">0.2.0"
        self.assertEqual(package_json_dev_deps[0]['component'], '@babel/core')

    def test_dep_scope_production(self):
        """
        Run a dependency scan of the current directory, then parse those results
        """
        # with open('scanoss-com.pem', 'rb') as f:
        #     root_certs = f.read()
        if MyTestCase.TEST_LOCAL:
            server_type = 'local'
            grpc_client = ScanossGrpc(debug=True, url='localhost:50051')
        else:
            server_type = 'remote'
            grpc_client = ScanossGrpc(debug=True)
        sc_deps = ScancodeDeps(debug=True)
        threaded_deps = ThreadedDependencies(sc_deps, grpc_client, '.', debug=True, trace=True)
        self.assertTrue(threaded_deps.run(what_to_scan='.', wait=True, dep_scope=SCOPE.PRODUCTION))
        deps = threaded_deps.responses
        files = deps.get('files')
        package_json_deps = files[0]['dependencies']
        requirements_txt_deps = files[1].get('dependencies', [])
        print(f'Dependency results for: ({files[0]["file"]}), dependencies: {package_json_deps}')
        print(f'Dependency results for: ({files[1]["file"]}), dependencies: {requirements_txt_deps}')

        self.assertNotEquals(len(requirements_txt_deps), 5)
        self.assertEqual(len(package_json_deps), 2)

        self.assertEqual(package_json_deps[0]['component'], 'uuid')
        self.assertEqual(package_json_deps[1]['component'], 'xml-js')

    def test_dep_scope_include(self):
        """
        Run a dependency scan of the current directory, then parse those results
        """
        # with open('scanoss-com.pem', 'rb') as f:
        #     root_certs = f.read()
        if MyTestCase.TEST_LOCAL:
            server_type = 'local'
            grpc_client = ScanossGrpc(debug=True, url='localhost:50051')
        else:
            server_type = 'remote'
            grpc_client = ScanossGrpc(debug=True)
        sc_deps = ScancodeDeps(debug=True)
        threaded_deps = ThreadedDependencies(sc_deps, grpc_client, '.', debug=True, trace=True)
        self.assertTrue(threaded_deps.run(what_to_scan='.', wait=True, dep_scope_include='dependencies'))
        deps = threaded_deps.responses
        files = deps.get('files')
        package_json_deps = files[0]['dependencies']
        requirements_txt_deps = files[1].get('dependencies', [])
        print(f'Dependency results for: ({files[0]["file"]}), dependencies: {package_json_deps}')
        print(f'Dependency results for: ({files[1]["file"]}), dependencies: {requirements_txt_deps}')

        # requirements.txt dependencies should be empty due to the filter 'dependencies'
        self.assertEqual(len(requirements_txt_deps), 0)
        self.assertEqual(len(package_json_deps), 2)
        # Prod dependencies package.json file: "uuid" and "xml-js"
        self.assertEqual(package_json_deps[0]['component'], 'uuid')
        self.assertEqual(package_json_deps[1]['component'], 'xml-js')

    def test_dep_scope_exclude(self):
        """
        Run a dependency scan of the current directory, then parse those results
        """
        # with open('scanoss-com.pem', 'rb') as f:
        #     root_certs = f.read()
        if MyTestCase.TEST_LOCAL:
            server_type = 'local'
            grpc_client = ScanossGrpc(debug=True, url='localhost:50051')
        else:
            server_type = 'remote'
            grpc_client = ScanossGrpc(debug=True)
        sc_deps = ScancodeDeps(debug=True)
        threaded_deps = ThreadedDependencies(sc_deps, grpc_client, '.', debug=True, trace=True)
        self.assertTrue(threaded_deps.run(what_to_scan='.', wait=True, dep_scope_exclude='dependencies,install'))
        deps = threaded_deps.responses
        files = deps.get('files')
        package_json_deps = files[0]['dependencies']
        requirements_txt_deps = files[1].get('dependencies', [])
        print(f'Dependency results for: ({files[0]["file"]}), dependencies: {package_json_deps}')
        print(f'Dependency results for: ({files[1]["file"]}), dependencies: {requirements_txt_deps}')
        self.assertEqual(len(requirements_txt_deps), 0)

        ## Only dev dependencies should be presents because 'dependencies' and 'install' scopes are excluded
        self.assertEqual(len(package_json_deps), 1)

        # Prod dependencies package.json file: "uuid" and "xml-js"
        self.assertEqual(package_json_deps[0]['component'], '@babel/core')

    def test_dep_scope_override(self):
        """
        Run a dependency scan of the current directory, then parse those results
        """
        # with open('scanoss-com.pem', 'rb') as f:
        #     root_certs = f.read()
        if MyTestCase.TEST_LOCAL:
            server_type = 'local'
            grpc_client = ScanossGrpc(debug=True, url='localhost:50051')
        else:
            server_type = 'remote'
            grpc_client = ScanossGrpc(debug=True)
        sc_deps = ScancodeDeps(debug=True)
        threaded_deps = ThreadedDependencies(sc_deps, grpc_client, '.', debug=True, trace=True)
        self.assertTrue(
            threaded_deps.run(
                what_to_scan='.', wait=True, dep_scope=SCOPE.PRODUCTION, dep_scope_exclude='dependencies,install'
            )
        )
        deps = threaded_deps.responses
        files = deps.get('files')
        package_json_deps = files[0]['dependencies']
        requirements_txt_deps = files[1].get('dependencies', [])
        print(f'Dependency results for: ({files[0]["file"]}), dependencies: {package_json_deps}')
        print(f'Dependency results for: ({files[1]["file"]}), dependencies: {requirements_txt_deps}')
        self.assertEqual(len(requirements_txt_deps), 0)

        ## Only dev dependencies should be presents because 'dependencies' and 'install' scopes are excluded
        self.assertEqual(len(package_json_deps), 1)

        # Prod dependencies package.json file: "uuid" and "xml-js"
        self.assertEqual(package_json_deps[0]['component'], '@babel/core')

    def test_dependency_scan(self):
        """
        Run a dependency scan of the current directory. Dependencies should be returned without scopes
        """
        temp_dir = tempfile.gettempdir()
        file_name = 'dependency-result-output.json'
        output_file = os.path.join(temp_dir, file_name)
        sc_deps = ScancodeDeps(debug=True, trace=True)

        success = sc_deps.get_dependencies(what_to_scan='.', result_output=output_file)
        self.assertTrue(success)
        with open(output_file, 'r') as result:
            # Parse the JSON data from the file
            dependencies = json.load(result)
            files = dependencies.get('files')
            for file in files:
                purls = file.get('purls')
                contains_scope = any('scope' in purl for purl in purls)
                self.assertFalse(contains_scope)

        os.remove(output_file)


if __name__ == '__main__':
    unittest.main()
