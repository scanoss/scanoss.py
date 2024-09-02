"""
 SPDX-License-Identifier: MIT

   Copyright (c) 2023, SCANOSS

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

from scanoss.utils.colorize import colorize

from .scanossbase import ScanossBase

ARG_TO_FILTER_MAP = {
    "match_type": "id",
    "status": "status",
}


class Results(ScanossBase):
    def __init__(
        self,
        debug: bool = False,
        trace: bool = False,
        quiet: bool = False,
        file: str = None,
        match_type: str = None,
        status: str = None,
    ):
        """
        Handles parsing of scan result file

        :param debug: Debug
        :param trace: Trace
        :param quiet: Quiet
        :param filepath: Path to the results file
        :param match_type: Comma separated list of match type filters
        :param status: Comma separated list of status filters
        """
        super().__init__(debug, trace, quiet)
        self.data = self._load_and_transform(file)
        self.filters = self._load_filters(match_type=match_type, status=status)

    def _load_file(self, file: str) -> dict:
        with open(file, "r") as jsonfile:
            try:
                return json.load(jsonfile)
            except Exception as e:
                self.print_stderr(f"ERROR: Problem parsing input JSON: {e}")

    def _load_and_transform(self, file: str) -> list:
        raw_data = self._load_file(file)
        return self._transform_data(raw_data)

    def _transform_data(self, data: dict) -> list:
        result = []
        for filename, file_data in data.items():
            if file_data:
                file_obj = {"filename": filename}
                file_obj.update(file_data[0])
                result.append(file_obj)
        return result

    def _load_filters(self, **kwargs):
        filters = {key: None for key in kwargs}

        for key, value in kwargs.items():
            if value:
                filters[key] = self.__extract_comma_separated_values(value)

        return filters

    def __extract_comma_separated_values(self, values: str) -> dict:
        return [value.strip() for value in values.split(",")]

    def apply_filters(self):
        filtered_data = []
        for item in self.data:
            if self._item_matches_filters(item):
                filtered_data.append(item)
        self.data = filtered_data

        return self

    def _item_matches_filters(self, item):
        for filter_key, filter_value in self.filters.items():
            if not filter_value:
                continue

            item_value = item.get(ARG_TO_FILTER_MAP[filter_key])
            if isinstance(filter_value, list):
                if item_value not in filter_value:
                    return False
            elif item_value != filter_value:
                return False
        return True

    def check_for_precommit(self):
        if self.data:
            self._present_precommit_overview()
            exit(1)
        return self

    def _present_precommit_overview(self):
        self.print_stderr(
            f"{colorize(f"ERROR: Found {len(self.data)} potential open source results that may need your attention:", "RED")}"
        )
        for item in self.data:
            self.print_stderr(f"  - {item['filename']}")

        self.print_stderr(
            f"Run {colorize('scanoss-lui', "GREEN")} in the terminal to view the results in more detail."
        )
