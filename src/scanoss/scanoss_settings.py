"""
SPDX-License-Identifier: MIT

  Copyright (c) 2024, SCANOSS

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the 'Software'), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.
"""

import json
from pathlib import Path
from typing import List, TypedDict

from .scanossbase import ScanossBase


class BomEntry(TypedDict, total=False):
    purl: str
    path: str


class ScanossSettings(ScanossBase):
    """Handles the loading and parsing of the SCANOSS settings file"""

    def __init__(
        self,
        debug: bool = False,
        trace: bool = False,
        quiet: bool = False,
        filepath: str = None,
    ):
        """
        Args:
            debug (bool, optional): Debug. Defaults to False.
            trace (bool, optional): Trace. Defaults to False.
            quiet (bool, optional): Quiet. Defaults to False.
            filepath (str, optional): Path to settings file. Defaults to None.
        """

        super().__init__(debug, trace, quiet)
        self.data = {}
        self.settings_file_type = None
        self.scan_type = None

        if filepath:
            self.load_json_file(filepath)

    def load_json_file(self, filepath: str):
        """Load the scan settings file

        Args:
            filepath (str): Path to the SCANOSS settings file
        """
        json_file = Path(filepath).resolve()

        if not json_file.exists():
            self.print_stderr(f"Scan settings file not found: {filepath}")
            self.data = {}

        with open(json_file, "r") as jsonfile:
            self.print_debug(f"Loading scan settings from: {filepath}")
            try:
                self.data = json.load(jsonfile)
            except Exception as e:
                self.print_stderr(f"ERROR: Problem parsing input JSON: {e}")
        return self

    def set_file_type(self, file_type: str):
        """Set the file type in order to support both legacy SBOM.json and new scanoss.json files

        Args:
            file_type (str): 'legacy' or 'new'

        Raises:
            Exception: Invalid scan settings file, missing "components" or "bom"
        """
        self.settings_file_type = file_type
        if not self._is_valid_sbom_file:
            raise Exception(
                'Invalid scan settings file, missing "components" or "bom")'
            )
        return self

    def set_scan_type(self, scan_type: str):
        """Set the scan type to support legacy SBOM.json files

        Args:
            scan_type (str): 'identify' or 'exclude'
        """
        self.scan_type = scan_type
        return self

    def _is_valid_sbom_file(self):
        """Check if the scan settings file is valid

        Returns:
            bool: True if the file is valid, False otherwise
        """
        if not self.data.get("components") or not self.data.get("bom"):
            return False
        return True

    def _get_bom(self):
        """Get the Billing of Materials from the settings file

        Returns:
            dict: If using scanoss.json
            list: If using SBOM.json
        """
        if self.settings_file_type == "legacy":
            if isinstance(self.data, list):
                return self.data
            elif isinstance(self.data, dict) and self.data.get("components"):
                return self.data.get("components")
            else:
                return []
        return self.data.get("bom", {})

    def get_bom_include(self) -> List[BomEntry]:
        """Get the list of components to include in the scan

        Returns:
            list: List of components to include in the scan
        """
        if self.settings_file_type == "legacy":
            return self._get_bom()
        return self._get_bom().get("include", [])

    def get_bom_remove(self) -> List[BomEntry]:
        """Get the list of components to remove from the scan

        Returns:
            list: List of components to remove from the scan
        """
        if self.settings_file_type == "legacy":
            return self._get_bom()
        return self._get_bom().get("remove", [])

    def get_sbom(self):
        """Get the SBOM to be sent to the SCANOSS API

        Returns:
            dict: SBOM
        """
        if not self.data:
            return None
        return {
            "scan_type": self.scan_type,
            "assets": json.dumps(self._get_sbom_assets()),
        }

    def _get_sbom_assets(self):
        """Get the SBOM assets

        Returns:
            List: List of SBOM assets
        """
        if self.scan_type == "identify":
            return self.normalize_bom_entries(self.get_bom_include())
        return self.normalize_bom_entries(self.get_bom_remove())

    @staticmethod
    def normalize_bom_entries(bom_entries) -> List[BomEntry]:
        """Normalize the BOM entries

        Args:
            bom_entries (List[Dict]): List of BOM entries

        Returns:
            List: Normalized BOM entries
        """
        normalized_bom_entries = []
        for entry in bom_entries:
            normalized_bom_entries.append(
                {
                    "purl": entry.get("purl", ""),
                }
            )
        return normalized_bom_entries
