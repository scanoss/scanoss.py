"""
 SPDX-License-Identifier: GPL-2.0-or-later

   Copyright (C) 2018-2021 SCANOSS LTD

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import os
import sys
import threading
import queue

from typing import Dict, List
from dataclasses import dataclass
from progress.bar import Bar
from progress.spinner import Spinner

from .scanossapi import ScanossApi

WFP_FILE_START = "file="
MAX_ALLOWED_THREADS = 30

@dataclass
class ThreadedScanning(object):
    """
    Threaded class for running Scanning in parallel (from a queue)
    WFP scan requests are loaded into the input queue.
    Multiple threads pull messages off this queue, process the request and put the results into an output queue
    """
    inputs: queue.Queue = queue.Queue()
    output: queue.Queue = queue.Queue()

    def __init__(self, scanapi :ScanossApi, debug: bool = False, trace: bool = False, quiet: bool = False,
                 nb_threads: int = 5
                 ) -> None:
        """
        Initialise the ThreadedScanning class
        :param scanapi: SCANOSS API to send scan requests to
        :param debug: enable debug (default False)
        :param trace: enable trace (default False)
        :param quiet: enable quiet mode (default False)
        :param nb_threads: Number of thread to run (default 5)
        """
        self.scanapi = scanapi
        self.debug = debug
        self.trace = trace
        self.quiet = quiet
        self.nb_threads = nb_threads
        self.bar = None
        self.errors = False
        if nb_threads > MAX_ALLOWED_THREADS:
            self.print_msg(f'Warning: Requested threads too large: {nb_threads}. Reducing to {MAX_ALLOWED_THREADS}')
            self.nb_threads = MAX_ALLOWED_THREADS

    @staticmethod
    def print_stderr(*args, **kwargs):
        """
        Print the given message to STDERR
        """
        print(*args, file=sys.stderr, **kwargs)

    @staticmethod
    def __count_files_in_wfp(wfp: str):
        """
        Count the number of files in the WFP that need to be processed
        :param wfp: WFP string
        :return: number of files in the WFP
        """
        count = 0
        if wfp:
            for line in wfp.split('\n'):
                if WFP_FILE_START in line:
                    count += 1
        return count

    def print_msg(self, *args, **kwargs):
        """
        Print message if quite mode is not enabled
        """
        if not self.quiet:
            self.print_stderr(*args, **kwargs)

    def print_debug(self, *args, **kwargs):
        """
        Print debug message if enabled
        """
        if self.debug:
            self.print_stderr(*args, **kwargs)

    def print_trace(self, *args, **kwargs):
        """
        Print trace message if enabled
        """
        if self.trace:
            self.print_stderr(*args, **kwargs)

    def set_bar(self, bar: Bar) -> None:
        """
        Set the Progress Bar to display progress while scanning
        :param bar: Progress Bar object
        """
        self.bar = bar

    def update_bar(self, amount: int) -> None:
        """
        Update the Progress Bar progress
        :param amount: amount of progress to update
        """
        if self.bar:
            self.bar.next(amount)

    def queue_add(self, wfp: str) -> None:
        """
        Add requests to the queue
        :param wfp: WFP to add to queue
        """
        self.inputs.put(wfp)

    @property
    def responses(self) -> List[Dict]:
        """
        Get all responses back from the completed threads
        :return: List of JSON objects
        """
        return list(self.output.queue)

    def run(self) -> bool:
        """
        Initiate the threads and process all pending requests
        :return: True if successful, False if error encountered
        """
        qsize = self.inputs.qsize()
        if qsize < self.nb_threads:
            self.print_debug(f'Input queue ({qsize}) smaller than requested threads: {self.nb_threads}. '
                             f'Reducing to queue size.')
            self.nb_threads = qsize
        else:
            self.print_debug(f'Starting {self.nb_threads} threads to process {qsize} requests...')
        try:
            for i in range(0, self.nb_threads):
                threading.Thread(target=self.worker_post, daemon=True).start()
        except Exception as e:
            self.print_stderr(f'ERROR: Problem running threaded scanning: {e}')
            self.errors = True
        self.inputs.join()

        return False if self.errors else True

    def worker_post(self) -> None:
        """
        Take each request and process it
        :return: None
        """
        current_thread = threading.get_ident()
        self.print_trace(f'Starting worker {current_thread}...')
        while not self.inputs.empty():
            self.print_trace(f'Processing input request...')
            try:
                wfp = self.inputs.get()
                count = self.__count_files_in_wfp(wfp)
                resp = self.scanapi.scan(wfp, scan_id=current_thread)
                if resp:
                    self.output.put(resp)  # Store the output response to later collection
                self.update_bar(count)
                self.inputs.task_done()
                self.print_trace(f'Request complete.')
            except Exception as e:
                ThreadedScanning.print_stderr(f'ERROR: Problem encountered running scan: {e}')
                self.errors = True

#
# End of ThreadedScanning Class
#