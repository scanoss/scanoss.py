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
import queue
import threading
from dataclasses import dataclass
from enum import Enum
from typing import Dict

from .scancodedeps import ScancodeDeps
from .scanossbase import ScanossBase
from .scanossgrpc import ScanossGrpc

DEP_FILE_PREFIX = 'file='  # Default prefix to signify an existing parsed dependency file

DEV_DEPENDENCIES = {
    'dev',
    'test',
    'development',
    'provided',
    'runtime',
    'devDependencies',
    'dev-dependencies',
    'testImplementation',
    'testCompile',
    'Test',
    'require-dev',
}


# Define an enum class
class SCOPE(Enum):
    PRODUCTION = 'prod'
    DEVELOPMENT = 'dev'


@dataclass
class ThreadedDependencies(ScanossBase):
    """ """

    inputs: queue.Queue = queue.Queue()
    output: queue.Queue = queue.Queue()

    def __init__(  # noqa: PLR0913
        self,
        sc_deps: ScancodeDeps,
        grpc_api: ScanossGrpc,
        what_to_scan: str = None,
        debug: bool = False,
        trace: bool = False,
        quiet: bool = False,
    ) -> None:
        """ """
        super().__init__(debug, trace, quiet)
        self.sc_deps = sc_deps
        self.grpc_api = grpc_api
        self.what_to_scan = what_to_scan
        self._thread = None
        self._errors = False

    @property
    def responses(self) -> Dict:
        """
        Get all responses back from the completed threads
        :return: JSON object
        """
        responses = list(self.output.queue)
        if responses:
            for resp in responses:
                return resp
        return None

    def run(
        self,
        what_to_scan: str = None,
        deps_file: str = None,
        wait: bool = True,
        dep_scope: SCOPE = None,
        dep_scope_include: str = None,
        dep_scope_exclude: str = None,
    ) -> bool:
        """
        Initiate a background scan for the specified file/dir
        :param dep_scope_exclude: comma separated list of dependency scopes to exclude
        :param dep_scope_include: comma separated list of dependency scopes to include
        :param dep_scope: Enum dependency scope to use
        :param what_to_scan: file/folder to scan
        :param deps_file: file to decorate instead of scan (overrides what_to_scan option)
        :param wait: wait for completion
        :return: True if successful, False if error encountered
        """
        what_to_scan = what_to_scan if what_to_scan else self.what_to_scan
        self._errors = False
        try:
            if deps_file:  # Decorate the given dependencies file
                self.print_msg(f'Decorating {deps_file} dependencies...')
                self.inputs.put(f'{DEP_FILE_PREFIX}{deps_file}')  # Add to queue and have parent wait on it
            else:  # Search for dependencies to decorate
                self.print_msg(f'Searching {what_to_scan} for dependencies...')
                self.inputs.put(what_to_scan)
                # Add to queue and have parent wait on it
            self._thread = threading.Thread(
                target=self.scan_dependencies(dep_scope, dep_scope_include, dep_scope_exclude), daemon=True
            )
            self._thread.start()
        except Exception as e:
            self.print_stderr(f'ERROR: Problem running threaded dependencies: {e}')
            self._errors = True
        if wait and not self._errors:  # Wait for all inputs to complete
            self.complete()
        return False if self._errors else True

    def filter_dependencies(self, deps, filter_dep) -> json:
        files = deps.get('files', [])
        # Iterate over files and their purls
        for file in files:
            if 'purls' in file:
                # Filter purls with scope 'dependencies' and remove the scope field
                file['purls'] = [
                    {key: value for key, value in purl.items() if key != 'scope'}
                    for purl in file['purls']
                    if filter_dep(purl.get('scope'))
                ]
        # End of for loop

        return {'files': [file for file in deps.get('files', []) if file.get('purls')]}

    def filter_dependencies_by_scopes(
        self, deps: json, dep_scope: SCOPE = None, dep_scope_include: str = None, dep_scope_exclude: str = None
    ) -> json:
        # Predefined set of scopes to filter

        # Include all scopes
        include_all = (dep_scope is None or dep_scope == '') and dep_scope_include is None and dep_scope_exclude is None
        ## All dependencies, remove scope key
        if include_all:
            return self.filter_dependencies(deps, lambda purl: True)

        # Use default list of scopes if a custom list is not set
        if (dep_scope is not None and dep_scope != '') and dep_scope_include is None and dep_scope_exclude is None:
            return self.filter_dependencies(
                deps,
                lambda purl: (dep_scope == SCOPE.PRODUCTION and purl not in DEV_DEPENDENCIES)
                or dep_scope == SCOPE.DEVELOPMENT
                and purl in DEV_DEPENDENCIES,
            )

        if (
            (dep_scope_include is not None and dep_scope_include != '')
            or dep_scope_exclude is not None
            and dep_scope_exclude != ''
        ):
            # Create sets from comma-separated strings, if provided
            exclude = set(dep_scope_exclude.split(',')) if dep_scope_exclude else set()
            include = set(dep_scope_include.split(',')) if dep_scope_include else set()

            # Define a lambda function that checks the inclusion/exclusion logic
            return self.filter_dependencies(
                deps, lambda purl: (exclude and purl not in exclude) or (not exclude and purl in include)
            )
        return None

    def scan_dependencies(  # noqa: PLR0912
        self, dep_scope: SCOPE = None, dep_scope_include: str = None, dep_scope_exclude: str = None
    ) -> None:
        """
        Scan for dependencies from the given file/dir or from an input file (from the input queue).
        """
        # TODO refactor to simplify branches based on PLR0912
        current_thread = threading.get_ident()
        self.print_trace(f'Starting dependency worker {current_thread}...')
        try:
            what_to_scan = self.inputs.get(timeout=5)  # Begin processing the dependency request
            deps = None
            if what_to_scan.startswith(DEP_FILE_PREFIX):  # We have a pre-parsed dependency file, load it
                deps = self.sc_deps.load_from_file(what_to_scan.strip(DEP_FILE_PREFIX))
            elif not self.sc_deps.run_scan(what_to_scan=what_to_scan):
                self._errors = True
            else:
                deps = self.sc_deps.produce_from_file()
                if dep_scope is not None:
                    self.print_debug(f'Filtering {dep_scope.name} dependencies')
                if dep_scope_include is not None:
                    self.print_debug(f"Including dependencies with '{dep_scope_include.split(',')}' scopes")
                if dep_scope_exclude is not None:
                    self.print_debug(f"Excluding dependencies with '{dep_scope_exclude.split(',')}' scopes")
                deps = self.filter_dependencies_by_scopes(deps, dep_scope, dep_scope_include, dep_scope_exclude)

            if not self._errors:
                if deps is None:
                    self.print_stderr(f'Problem searching for dependencies for: {what_to_scan}')
                    self._errors = True
                elif not deps or len(deps.get('files', [])) == 0:
                    self.print_debug(f'No dependencies found to decorate for: {what_to_scan}')
                else:
                    decorated_deps = self.grpc_api.get_dependencies(deps)
                    if decorated_deps:
                        self.output.put(decorated_deps)
                    else:
                        self._errors = True
        except Exception as e:
            self.print_stderr(f'ERROR: Problem encountered running dependency scan: {e}')
            self._errors = True
        finally:
            self.sc_deps.remove_interim_file()
            self.inputs.task_done()
        self.print_trace(f'Dependency thread complete ({current_thread}).')

    def complete(self) -> bool:
        """
        Wait for input queue to complete processing and complete the worker thread
        """
        try:
            self.inputs.join()
            self._thread.join(timeout=5)
        except Exception as e:
            self.print_stderr(f'WARNING: Issue encountered terminating dependency worker thread: {e}')
            self._errors = True
        return True if not self._errors else False


#
# End of ThreadedDependencies Class
#
