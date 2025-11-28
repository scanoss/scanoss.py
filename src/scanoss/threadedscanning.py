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

import atexit
import os
import queue
import sys
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Dict, List

from progress.bar import Bar

from .scanossapi import ScanossApi
from .scanossbase import ScanossBase

WFP_FILE_START = 'file='
MAX_ALLOWED_THREADS = (
    int(os.environ.get('SCANOSS_MAX_ALLOWED_THREADS')) if os.environ.get('SCANOSS_MAX_ALLOWED_THREADS') else 30
)


@dataclass
class ThreadedScanning(ScanossBase):
    """
    Threaded class for running Scanning in parallel (from a queue)
    WFP scan requests are loaded into the input queue.
    Multiple threads pull messages off this queue, process the request and put the results into an output queue
    """

    bar: Bar = None

    def __init__(
        self, scanapi: ScanossApi, debug: bool = False, trace: bool = False, quiet: bool = False, nb_threads: int = 5
    ) -> None:
        """
        Initialise the ThreadedScanning class
        :param scanapi: SCANOSS API to send scan requests to
        :param debug: enable debug (default False)
        :param trace: enable trace (default False)
        :param quiet: enable quiet mode (default False)
        :param nb_threads: Number of thread to run (default 5)
        """
        super().__init__(debug, trace, quiet)
        self.inputs = queue.Queue()
        self.output = queue.Queue()
        self.scanapi = scanapi
        self.nb_threads = nb_threads
        self._isatty = sys.stderr.isatty()
        self._bar_count = 0
        self._errors = False
        self._lock = threading.Lock()
        self._stop_event = threading.Event()  # Control when scanning threads should terminate
        self._stop_scanning = threading.Event()  # Control if the parent process should abort scanning
        self._threads = []
        # Batch scanning session management
        self._session_id = None
        self._total_chunks = 0
        self._processed_chunks = 0
        self._final_chunk = None  # WFP chunk reserved for sequential final submission
        if nb_threads > MAX_ALLOWED_THREADS:
            self.print_msg(f'Warning: Requested threads too large: {nb_threads}. Reducing to {MAX_ALLOWED_THREADS}')
            self.nb_threads = MAX_ALLOWED_THREADS
        # Register cleanup to ensure progress bar is finished on exit
        atexit.register(self.complete_bar)

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

    def create_bar(self, file_count: int):
        if not self.quiet and self._isatty and not self.bar:
            self.bar = Bar('Scanning', max=file_count)
            self.bar.next(self._bar_count)

    def complete_bar(self):
        if self.bar:
            self.bar.finish()

    def __del__(self):
        """Ensure progress bar is cleaned up when object is destroyed"""
        try:
            self.complete_bar()
        except Exception:
            pass  # Ignore errors during cleanup

    def set_bar(self, bar: Bar) -> None:
        """
        Set the Progress Bar to display progress while scanning
        :param bar: Progress Bar object
        """
        self.bar = bar

    def update_bar(self, amount: int = 0, create: bool = False, file_count: int = 0) -> None:
        """
        Update the Progress Bar progress
        :param amount: amount of progress to update
        :param create: create the bar if requested
        :param file_count: file count
        """
        try:
            self._lock.acquire()
            try:
                if create and not self.bar:
                    self.create_bar(file_count)
                elif self.bar:
                    self.bar.next(amount)
                self._bar_count += amount
            finally:
                self._lock.release()
        except Exception as e:
            self.print_debug(f'Warning: Update status bar lock failed: {e}. Ignoring.')

    def queue_add(self, wfp: str) -> None:
        """
        Add requests to the queue
        :param wfp: WFP to add to queue
        """
        if wfp is None or wfp == '':
            self.print_stderr('Warning: empty WFP. Skipping from scan...')
        else:
            self.inputs.put(wfp)

    def get_queue_size(self) -> int:
        return self.inputs.qsize()

    def stop_scanning(self) -> bool:
        """
        Check if we should keep scanning or not
        """
        return self._stop_scanning.is_set()

    @property
    def responses(self) -> List[Dict]:
        """
        Get all responses back from the completed threads
        :return: List of JSON objects
        """
        return list(self.output.queue)

    def run(self, wait: bool = True) -> bool:
        """
        Initiate the threads and process all pending requests
        :return: True if successful, False if error encountered
        """
        # Generate session ID for batch scanning
        self._session_id = str(uuid.uuid4())
        qsize = self.inputs.qsize()
        self._total_chunks = qsize
        self.print_debug(f'Batch scan session ID: {self._session_id}')

        # Extract the last chunk to submit separately (eliminates race condition)
        self._final_chunk = None
        if qsize > 0:
            # Temporarily extract all items to get the last one
            temp_chunks = []
            while not self.inputs.empty():
                temp_chunks.append(self.inputs.get())

            # Mark all extracted items as done - we're taking over their management
            for _ in temp_chunks:
                self.inputs.task_done()

            # Hold back the last chunk for sequential submission
            self._final_chunk = temp_chunks.pop() if temp_chunks else None

            # Re-queue all other chunks for worker threads (creates new tasks)
            for chunk in temp_chunks:
                self.inputs.put(chunk)

            # Update counts: workers process N-1 chunks
            qsize = len(temp_chunks)
            self._total_chunks = qsize
            self.print_debug(f'Reserved final chunk. Workers will process {qsize} chunks.')

        if qsize < self.nb_threads:
            self.print_debug(
                f'Input queue ({qsize}) smaller than requested threads: {self.nb_threads}. Reducing to queue size.'
            )
            self.nb_threads = qsize
        else:
            self.print_debug(f'Starting {self.nb_threads} threads to process {qsize} requests...')
        try:
            for i in range(0, self.nb_threads):
                t = threading.Thread(target=self.worker_post, daemon=True)
                self._threads.append(t)
                t.start()
        except Exception as e:
            self.print_stderr(f'ERROR: Problem running threaded scanning: {e}')
            self._errors = True
        if wait:  # Wait for all inputs to complete
            self.complete()
        return False if self._errors else True

    def complete(self) -> bool:
        """
        Wait for input queue to complete processing and complete the worker threads
        """
        self.inputs.join()  # Wait for all worker chunks to be processed

        # Now submit the final chunk sequentially (eliminates race condition)
        if self._final_chunk and not self._errors:
            try:
                self.print_debug('Submitting final chunk with is_final_chunk=True...')
                self.scanapi.scan_batch(
                    self._final_chunk, session_id=self._session_id, is_final_chunk=True
                )
                # Update progress bar for final chunk
                count = self.__count_files_in_wfp(self._final_chunk)
                self.update_bar(count)
                self.print_debug('Final chunk submitted successfully.')
            except Exception as e:
                self.print_stderr(f'ERROR: Failed to submit final chunk: {e}')
                self._errors = True

        self._stop_event.set()  # Tell the worker threads to stop
        try:
            for t in self._threads:  # Complete the threads
                t.join(timeout=5)
        except Exception as e:
            self.print_stderr(f'WARNING: Issue encountered terminating scanning worker threads: {e}')
            self._errors = True

        # After all chunks are submitted, poll for results
        if not self._errors and self._session_id:
            self._poll_for_results()

        return False if self._errors else True

    def _poll_for_results(self) -> None:
        """
        Poll the batch scanning API for results and add them to the output queue
        """
        try:
            self.print_debug(f'Polling for batch scan results (session: {self._session_id})...')
            results = self.scanapi.poll_scan_status(self._session_id)
            if results:
                # Put the batch results into the output queue
                self.output.put(results)
                self.print_debug('Batch scan results received and queued.')
            else:
                self.print_stderr('Warning: No results returned from batch scan.')
        except Exception as e:
            self.print_stderr(f'ERROR: Failed to poll batch scan results: {e}')
            self._errors = True

    def worker_post(self) -> None:
        """
        Take each request and process it
        :return: None
        """
        current_thread = threading.get_ident()
        self.print_trace(f'Starting worker {current_thread}...')
        api_error = False
        while not self._stop_event.is_set():
            wfp = None
            if not self.inputs.empty():  # Only try to get a message if there is one on the queue
                try:
                    wfp = self.inputs.get(timeout=5)
                    if api_error:  # API error encountered, so stop processing anymore requests
                        self.inputs.task_done()  # remove request from the queue
                    else:
                        self.print_trace(f'Processing input request ({current_thread})...')
                        count = self.__count_files_in_wfp(wfp)
                        if wfp is None or wfp == '':
                            self.print_stderr(f'Warning: Empty WFP in request input: {wfp}')

                        # Track progress atomically (for debugging)
                        with self._lock:
                            self._processed_chunks += 1
                            chunk_num = self._processed_chunks

                        # Send WFP chunk to batch API (workers never send final chunk)
                        self.scanapi.scan_batch(
                            wfp, session_id=self._session_id, is_final_chunk=False, scan_id=current_thread
                        )

                        self.update_bar(count)
                        self.inputs.task_done()
                        self.print_trace(
                            f'Batch chunk submitted ({current_thread}, chunk {chunk_num}/{self._total_chunks}).'
                        )
                except queue.Empty:
                    self.print_stderr(f'No message available to process ({current_thread}). Checking again...')
                except Exception as e:
                    self.print_stderr(f'ERROR: Problem encountered running scan: {e}. Aborting current thread.')
                    self._errors = True
                    if wfp:
                        self.inputs.task_done()  # If there was a WFP being processed, remove it from the queue
                    api_error = True  # Stop processing anymore work requests
                    self._stop_scanning.set()  # Tell the parent process to abort scanning
            else:
                time.sleep(1)  # Sleep while waiting for the queue depth to build up
        self.print_trace(f'Thread complete ({current_thread}).')


#
# End of ThreadedScanning Class
#
