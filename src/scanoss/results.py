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
from typing import Any, Dict, List

from .scanossbase import ScanossBase

MATCH_TYPES = ["file", "snippet"]
STATUSES = ["pending", "identified"]


AVAILABLE_FILTER_VALUES = {
    "match_type": [e for e in MATCH_TYPES],
    "status": [e for e in STATUSES],
}


ARG_TO_FILTER_MAP = {
    "match_type": "id",
    "status": "status",
}

PENDING_IDENTIFICATION_FILTERS = {
    "match_type": ["file", "snippet"],
    "status": ["pending"],
}

AVAILABLE_OUTPUT_FORMATS = ["json", "plain"]


class Results(ScanossBase):

    def __init__(
        self,
        debug: bool = False,
        trace: bool = False,
        quiet: bool = False,
        filepath: str = None,
        match_type: str = None,
        status: str = None,
        output_file: str = None,
        output_format: str = None,
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
        self.data = self._load_and_transform(filepath)
        self.filters = self._load_filters(match_type=match_type, status=status)
        self.output_file = output_file
        self.output_format = output_format

    def _load_file(self, file: str) -> Dict[str, Any]:
        with open(file, "r") as jsonfile:
            try:
                return json.load(jsonfile)
            except Exception as e:
                self.print_stderr(f"ERROR: Problem parsing input JSON: {e}")

    def _load_and_transform(self, file: str) -> List[Dict[str, Any]]:
        """
        Load the file and transform the data into a list of dictionaries with the filename and the file data
        """

        raw_data = self._load_file(file)
        return self._transform_data(raw_data)

    @staticmethod
    def _transform_data(data: dict) -> list:
        result = []
        for filename, file_data in data.items():
            if file_data:
                file_obj = {'filename': filename}
                file_obj.update(file_data[0])
                result.append(file_obj)
        return result

    def _load_filters(self, **kwargs):
        filters = {}

        for key, value in kwargs.items():
            if value:
                filters[key] = self._extract_comma_separated_values(value)

        return filters

    @staticmethod
    def _extract_comma_separated_values(values: str):
        return [value.strip() for value in values.split(",")]

    def apply_filters(self):
        filtered_data = []
        for item in self.data:
            if self._item_matches_filters(item):
                filtered_data.append(item)
        self.data = filtered_data

        return self

    def _item_matches_filters(self, item):
        for filter_key, filter_values in self.filters.items():
            if not filter_values:
                continue

            self._validate_filter_values(filter_key, filter_values)

            item_value = item.get(ARG_TO_FILTER_MAP[filter_key])
            if isinstance(filter_values, list):
                if item_value not in filter_values:
                    return False
            elif item_value != filter_values:
                return False
        return True

    @staticmethod
    def _validate_filter_values(filter_key: str, filter_value: list[str]):
        if any(
            value not in AVAILABLE_FILTER_VALUES.get(filter_key, [])
            for value in filter_value
        ):
            valid_values = ", ".join(AVAILABLE_FILTER_VALUES.get(filter_key, []))
            raise Exception(
                f"ERROR: Invalid filter value '{filter_value}' for filter '{filter_key.value}'. "
                f"Valid values are: {valid_values}"
            )

    def get_pending_identifications(self):
        self.filters = PENDING_IDENTIFICATION_FILTERS
        self.apply_filters()

        return self

    def has_results(self):
        return bool(self.data)

    def present(self, output_format: str = None, output_file: str = None):
        file_path = output_file or self.output_file
        fmt = output_format or self.output_format

        if fmt and fmt not in AVAILABLE_OUTPUT_FORMATS:
            raise Exception(
                f"ERROR: Invalid output format '{output_format}'. Valid values are: {', '.join(AVAILABLE_OUTPUT_FORMATS)}"
            )

        if fmt == 'json':
            return self._present_json(file_path)
        elif fmt == 'plain':
            return self._present_plain(file_path)
        else:
            return self._present_stdout()

    def _present_json(self, file: str = None):
        self.print_to_file_or_stdout(
            json.dumps(self._format_json_output(), indent=2), file
        )

    def _format_json_output(self):
        """
        Format the output data into a JSON object
        """

        formatted_data = []
        for item in self.data:
            formatted_data.append(
                {
                    'file': item['filename'],
                    'status': item['status'] if 'status' in item else None,
                    'match_type': item['id'],
                    'matched': item['matched'] if 'matched' in item else None,
                }
            )
        return {'results': formatted_data, 'total': len(formatted_data)}

    def _present_plain(self, file: str = None):
        if not self.data:
            return self.print_stderr("No results to present")
        self.print_to_file_or_stdout(self._format_plain_output(), file)

    def _present_stdout(self):
        if not self.data:
            return self.print_stderr("No results to present")
        self.print_to_file_or_stdout(self._format_plain_output())

    def _format_plain_output(self):
        """
        Format the output data into a plain text
        """

        formatted = ""
        for item in self.data:
            formatted += f"{self._format_plain_output_item(item)} \n"
        return formatted

    @staticmethod
    def _format_plain_output_item(item):
        return (
            f"File: {item['filename']}\n"
            f"Match type: {item['id']}\n"
            f"Status: {item.get('status', 'N/A')}\n"
            f"Matched: {item.get('matched', 'N/A')}\n"
        )
