"""
 SPDX-License-Identifier: MIT

   Copyright (c) 2024, SCANOSS

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

from .scanoss_settings import ScanossSettings
from .scanossbase import ScanossBase


class ScanPostProcessor(ScanossBase):
    """Handles post-processing of the scan results"""

    def __init__(
        self,
        scan_settings: ScanossSettings,
        debug: bool = False,
        trace: bool = False,
        quiet: bool = False,
        results: dict = None,
    ):
        """
        Args:
            scan_settings (ScanossSettings): Scan settings object
            debug (bool, optional): Debug mode. Defaults to False.
            trace (bool, optional): Traces. Defaults to False.
            quiet (bool, optional): Quiet mode. Defaults to False.
            results (dict | str, optional): Results to be processed. Defaults to None.
        """
        super().__init__(debug, trace, quiet)
        self.scan_settings = scan_settings
        self.results = results

    def load_results(self, raw_results: dict):
        """Load the raw results

        Args:
            raw_results (dict): Raw scan results
        """
        self.results = raw_results
        return self

    def post_process(self):
        """Post-process the scan results

        Returns:
            dict: Processed results
        """
        self.remove_dismissed_files()
        return self.results

    def remove_dismissed_files(self):
        """Remove dismissed files in SCANOSS settings file from the results"""
        to_remove_files, to_remove_purls = (
            self.scan_settings.get_bom_remove_for_filtering()
        )

        if not to_remove_files and not to_remove_purls:
            return

        self.filter_files(to_remove_files, to_remove_purls)
        return self

    def filter_files(self, files: list, purls: list):
        """Filter files based on the provided list of files and purls

        Args:
            files (list): List of files to be filtered
            purls (list): List of purls to be filtered
        """
        filtered_results = {}

        for file_name in self.results:
            file = self.results.get(file_name)
            file = file[0] if isinstance(file, list) else file

            identified_purls = file.get("purl")
            if identified_purls and any(purl in purls for purl in identified_purls):
                continue
            elif file_name in files:
                continue

            filtered_results[file_name] = file

        self.results = filtered_results
        return self
