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

import threading
import queue
from typing import Dict
from dataclasses import dataclass

from .scancodedeps import ScancodeDeps
from .scanossbase import ScanossBase
from .scanossgrpc import ScanossGrpc


@dataclass
class ThreadedDependencies(ScanossBase):
    """

    """
    inputs: queue.Queue = queue.Queue()
    output: queue.Queue = queue.Queue()

    def __init__(self, sc_deps: ScancodeDeps, grpc_api: ScanossGrpc, what_to_scan: str = None, debug: bool = False,
                 trace: bool = False, quiet: bool = False) -> None:
        """

        """
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

    def run(self, what_to_scan: str = None, wait: bool = True) -> bool:
        """
        Initiate a background scan for the specified file/dir
        :param what_to_scan: file/folder to scan
        :param wait: wait for completion
        :return: True if successful, False if error encountered
        """
        what_to_scan = what_to_scan if what_to_scan else self.what_to_scan
        self._errors = False
        try:
            self.print_msg(f'Searching {what_to_scan} for dependencies...')
            self.inputs.put(what_to_scan)   # Set up an input queue to enable the parent to wait for completion
            self._thread = threading.Thread(target=self.scan_dependencies, daemon=True)
            self._thread.start()
        except Exception as e:
            self.print_stderr(f'ERROR: Problem running threaded dependencies: {e}')
            self._errors = True
        if wait and not self._errors:               # Wait for all inputs to complete
            self.complete()
        return False if self._errors else True

    def scan_dependencies(self) -> None:
        """
        Scan for dependencies from the given file/dir (from the input queue)
        """
        current_thread = threading.get_ident()
        self.print_trace(f'Starting dependency worker {current_thread}...')
        try:
            what_to_scan = self.inputs.get(timeout=5)                # Begin processing the dependency request
            if not self.sc_deps.run_scan(what_to_scan=what_to_scan):
                self._errors = True
            else:
                deps = self.sc_deps.produce_from_file()
                if deps is None:
                    self.print_stderr(f'Problem searching for dependencies for: {what_to_scan}')
                    self._errors = True
                elif not deps:
                    self.print_trace(f'No dependencies found to decorate for: {what_to_scan}')
                else:                         # TODO add API call to get dep data
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
