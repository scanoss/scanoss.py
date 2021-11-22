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
import sys
import threading
import queue
import time

from typing import Dict, List
from dataclasses import dataclass

from .scancodedeps import ScancodeDeps

@dataclass
class ThreadedDependencies(object):
    """

    """
    inputs: queue.Queue = queue.Queue()
    output: queue.Queue = queue.Queue()

    def __init__(self, sc_deps: ScancodeDeps, what_to_scan: str = None, debug: bool = False, trace: bool = False,
                 quiet: bool = False
                 ) -> None:
        """

        """
        self.sc_deps = sc_deps
        self.what_to_scan = what_to_scan
        self.debug = debug
        self.trace = trace
        self.quiet = quiet
        self._thread = None
        self._errors = False

    @staticmethod
    def print_stderr(*args, **kwargs) -> None:
        """
        Print the given message to STDERR
        """
        print(*args, file=sys.stderr, **kwargs)

    def print_msg(self, *args, **kwargs) -> None:
        """
        Print message if quite mode is not enabled
        """
        if not self.quiet:
            self.print_stderr(*args, **kwargs)

    def print_debug(self, *args, **kwargs) -> None:
        """
        Print debug message if enabled
        """
        if self.debug:
            self.print_stderr(*args, **kwargs)

    def print_trace(self, *args, **kwargs) -> None:
        """
        Print trace message if enabled
        """
        if self.trace:
            self.print_stderr(*args, **kwargs)

    @property
    def responses(self) -> Dict:
        """
        Get all responses back from the completed threads
        :return: JSON object
        """
        resps = list(self.output.queue)
        if resps:
            for resp in resps:
                return resp
        return None

    def run(self, what_to_scan: str = None, wait: bool = True) -> bool:
        """

        :return: True if successful, False if error encountered
        """
        what_to_scan = what_to_scan if what_to_scan else self.what_to_scan
        self._errors = False
        try:
            self.inputs.put(what_to_scan)   # Setup an input queue to enable the parent to wait for completion
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

        """
        current_thread = threading.get_ident()
        self.print_trace(f'Starting worker {current_thread}...')
        try:
            what_to_scan = self.inputs.get(timeout=5)                                      # Begin processing the dependency request
            if not self.sc_deps.run_scan(what_to_scan=what_to_scan):
                self._errors = True
            else:
                deps = self.sc_deps.produce_from_file()
                if not deps:
                    self._errors = True
                else:
                    self.output.put(deps)
        except Exception as e:
            ThreadedScanning.print_stderr(f'ERROR: Problem encountered running dependency scan: {e}')
            self._errors = True
        finally:
            self.sc_deps.remove_interim_file()
            self.inputs.task_done()
        self.print_trace(f'Thread complete ({current_thread}).')

    def complete(self) -> None:
        """
        Wait for input queue to complete processing and complete the worker thread
        """
        self.inputs.join()
        try:
            self._thread.join(timeout=5)
        except Exception as e:
            self.print_stderr(f'WARNING: Issue encountered terminating dependency worker thread: {e}')

#
# End of ThreadedDependencies Class
#
