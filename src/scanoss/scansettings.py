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
from typing import Any, Dict

from scanoss.scanossbase import ScanossBase

DEFAULT_SCAN_SETTINGS_FILE = "scanoss.json"


class ScanSettings(ScanossBase):
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
        self.data = self._load_json_file(filepath if filepath is not None else DEFAULT_SCAN_SETTINGS_FILE)

    def _load_json_file(self, filepath: str) -> Dict[str, Any]:
        file = f"{os.getcwd()}/{filepath}"

        if not os.path.exists(file):
            self.print_stderr(f"Scan settings file not found: {file}")
            return {}

        with open(file, "r") as jsonfile:
            self.print_stderr(f"Loading scan settings from: {file}")
            try:
                return json.load(jsonfile)
            except Exception as e:
                self.print_stderr(f"ERROR: Problem parsing input JSON: {e}")

    def _get_bom(self) -> Dict[str, Any]:
        return self.data.get("bom", {})

    def get_bom_include(self):
        return self._get_bom().get("include", [])

    def get_bom_remove(self):
        return self._get_bom().get("remove", [])

    def get_bom_include_purls(self):
        purls = []
        for include in self.get_bom_include():
            purls.append(include.get("purl", ""))
        return purls

    def get_bom_remove_purls(self):
        purls = []
        for remove in self.get_bom_remove():
            purls.append(remove.get("purl", ""))
        return purls


if __name__ == "__main__":
    scanoss = ScanSettings(filepath=".scanoss/scanoss.json")
    include_purls = scanoss.get_bom_include_purls()
    remove_purls = scanoss.get_bom_remove_purls()
    print(include_purls)
    print(remove_purls)
