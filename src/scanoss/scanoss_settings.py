"""
 SPDX-License-Identifier: MIT

   Copyright (c) 2021, SCANOSS

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
import os
from typing import Any, Dict

from scanoss.scanossbase import ScanossBase

DEFAULT_SCAN_SETTINGS_FILE = 'scanoss.json'


class ScanossSettings(ScanossBase):
    def __init__(
        self,
        debug: bool = False,
        trace: bool = False,
        quiet: bool = False,
        filepath: str = None,
    ):
        f"""
        Handles parsing of scan settings

        :param debug: Debug
        :param trace: Trace
        :param quiet: Quiet
        :param filepath: Path to the scan settings file (default: {DEFAULT_SCAN_SETTINGS_FILE})
        """

        super().__init__(debug, trace, quiet)
        self.data = None
        self.settings_file_type = None
        self.scan_type = None

        if filepath:
            self.load_json_file(filepath)

    def load_json_file(self, filepath: str):
        file = f'{os.getcwd()}/{filepath}'

        if not os.path.exists(file):
            self.print_stderr(f'Scan settings file not found: {file}')
            self.data = {}

        with open(file, 'r') as jsonfile:
            self.print_stderr(f'Loading scan settings from: {file}')
            try:
                self.data = json.load(jsonfile)
            except Exception as e:
                self.print_stderr(f'ERROR: Problem parsing input JSON: {e}')
        return self

    def set_file_type(self, file_type: str):
        """
        Set the file type in order to support both legacy SBOM.json and new scanoss.json files
        """
        self.settings_file_type = file_type
        if not self.is_valid_sbom_file:
            raise Exception(
                'Invalid scan settings file, missing "components" or "bom")'
            )
        return self

    def set_scan_type(self, scan_type: str):
        """
        Set the scan type to support legacy SBOM.json
        """
        self.scan_type = scan_type
        return self

    def is_valid_sbom_file(self):
        if not self.data.get('components') or not self.data.get('bom'):
            return False
        return True

    def _get_bom(self):
        if self.settings_file_type == 'legacy':
            return self.normalize_bom_entries(self.data.get('components', []))
        return self.data.get('bom', {})

    def get_bom_include(self):
        if self.settings_file_type == 'legacy':
            return self._get_bom()
        return self.normalize_bom_entries(self._get_bom().get('include', []))

    @staticmethod
    def normalize_bom_entries(bom_entries):
        normalized_bom_entries = []
        for entry in bom_entries:
            normalized_bom_entries.append(
                {
                    'purl': entry.get('purl', ''),
                }
            )
        return normalized_bom_entries

    def get_bom_remove(self):
        if self.settings_file_type == 'legacy':
            return self._get_bom()
        return self.normalize_bom_entries(self._get_bom().get('remove', []))

    def get_sbom(self):
        if not self.data:
            return None
        return {
            'scan_type': self.scan_type,
            'assets': json.dumps(self._get_sbom_assets()),
        }

    def _get_sbom_assets(self):
        if self.scan_type == 'identify':
            return self.get_bom_include()
        return self.get_bom_remove()
