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

from typing import List

from .scanoss_settings import BomEntry, ScanossSettings
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
        """Remove entries from the results based on files and/or purls specified in the SCANOSS settings file"""

        to_remove_entries = self.scan_settings.get_bom_remove()

        if not to_remove_entries:
            return

        self.results = {
            result_path: result
            for result_path, result in self.results.items()
            if not self._should_remove_result(result_path, result, to_remove_entries)
        }

    def _should_remove_result(
        self, result_path: str, result: dict, to_remove_entries: List[BomEntry]
    ) -> bool:
        """Check if a result should be removed based on the SCANOSS settings"""
        result = result[0] if isinstance(result, list) else result
        result_purls = result.get("purl", [])

        for to_remove_entry in to_remove_entries:
            to_remove_path = to_remove_entry.get("path")
            to_remove_purl = to_remove_entry.get("purl")

            if not to_remove_path and not to_remove_purl:
                continue

            # Bom entry has both path and purl
            if self._is_full_match(result_path, result_purls, to_remove_entry):
                self._print_removal_message(result_path, result_purls, to_remove_entry)
                return True

            # Bom entry has only purl
            if not to_remove_path and to_remove_purl in result_purls:
                self._print_removal_message(result_path, result_purls, to_remove_entry)
                return True

            # Bom entry has only path
            if not to_remove_purl and to_remove_path == result_path:
                self._print_removal_message(result_path, result_purls, to_remove_entry)
                return True

        return False

    def _print_removal_message(
        self, result_path: str, result_purls: List[str], to_remove_entry: BomEntry
    ) -> None:
        """Print a message about removing a result"""
        if to_remove_entry.get("path") and to_remove_entry.get("purl"):
            message = f"Removing '{result_path}' from the results. Full match found."
        elif to_remove_entry.get("purl"):
            message = f"Removing '{result_path}' from the results. Found PURL match."
        else:
            message = f"Removing '{result_path}' from the results. Found path match."

        self.print_msg(
            f"{message}\n"
            f"Details:\n"
            f"  - PURLs: {', '.join(result_purls)}\n"
            f"  - Path: '{result_path}'\n"
        )

    def _is_full_match(
        self,
        result_path: str,
        result_purls: List[str],
        bom_entry: BomEntry,
    ) -> bool:
        """Check if path and purl matches fully with the bom entry

        Args:
            result_path (str): Scan result path
            result_purls (List[str]): Scan result purls
            bom_entry (BomEntry): BOM entry to compare with

        Returns:
            bool: True if the path and purl match, False otherwise
        """

        if not result_purls:
            return False

        return bool(
            (bom_entry.get("purl") and bom_entry.get("path"))
            and (bom_entry.get("path") == result_path)
            and (bom_entry.get("purl") in result_purls)
        )
