"""
SPDX-License-Identifier: MIT

  Copyright (c) 2025, SCANOSS

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
import sys
from dataclasses import dataclass

from .scanossbase import ScanossBase
from .utils import scanoss_scan_results_utils



@dataclass
class Lines:
    begin: int

@dataclass
class Location:
    path: str
    lines: Lines

@dataclass
class CodeQuality:
    description: str
    check_name: str
    fingerprint: str
    severity: str
    location: Location

    def to_dict(self):
        """Convert to dictionary for JSON serialization."""
        return {
            "description": self.description,
            "check_name": self.check_name,
            "fingerprint": self.fingerprint,
            "severity": self.severity,
            "location": {
                "path": self.location.path,
                "lines": {
                    "begin": self.location.lines.begin
                }
            }
        }

class GitLabQualityReport(ScanossBase):
    """
    GitLabCodeQuality management class
    Handle all interaction with GitLab Code Quality Report formatting
    """

    def __init__(self, debug: bool = False, trace: bool = False, quiet: bool = False):
        """
        Initialise the GitLabCodeQuality class
        """
        super().__init__(debug, trace, quiet)


    def _get_code_quality(self, file_name: str, result: dict) -> CodeQuality or None:
        if not result.get('file_hash'):
            self.print_debug(f"Warning: no hash found for result: {result}")
            return None

        if result.get('id') == 'file':
            description = f"File match found in: {file_name}"
            return CodeQuality(
                description=description,
                check_name=file_name,
                fingerprint=result.get('file_hash'),
                severity="info",
                location=Location(
                    path=file_name,
                    lines = Lines(
                        begin= 1
                    )
                )
            )

        if not result.get('lines'):
            self.print_debug(f"Warning: No lines found for result: {result}")
            return None
        lines = scanoss_scan_results_utils.get_lines(result.get('lines'))
        if len(lines) == 0:
            self.print_debug(f"Warning: empty lines for result: {result}")
            return None
        end_line = lines[len(lines) - 1] if len(lines) > 1 else lines[0]
        description = f"Snippet found in: {file_name} - lines {lines[0]}-{end_line}"
        return CodeQuality(
            description=description,
            check_name=file_name,
            fingerprint=result.get('file_hash'),
            severity="info",
            location=Location(
                path=file_name,
                lines=Lines(
                    begin=lines[0]
                )
            )
        )

    def _write_output(self, data: list[CodeQuality], output_file: str = None) -> bool:
        """Write the Gitlab Code Quality Report to output."""
        try:
            json_data = [item.to_dict() for item in data]
            file = open(output_file, 'w') if output_file else sys.stdout
            print(json.dumps(json_data, indent=2), file=file)
            if output_file:
                file.close()
            return True
        except Exception as e:
            self.print_stderr(f'Error writing output: {str(e)}')
            return False

    def _produce_from_json(self, data: dict, output_file: str = None) -> bool:
        code_quality = []
        for file_name, results in data.items():
            for result in results:
                if not result.get('id'):
                    self.print_debug(f"Warning: No ID found for result: {result}")
                    continue
                if result.get('id') != 'snippet' and result.get('id') != 'file':
                    self.print_debug(f"Skipping non-snippet/file match: {result}")
                    continue
                code_quality_item = self._get_code_quality(file_name, result)
                if code_quality_item:
                    code_quality.append(code_quality_item)
                else:
                    self.print_debug(f"Warning: No Code Quality found for result: {result}")
        self._write_output(data=code_quality,output_file=output_file)
        return True

    def _produce_from_str(self, json_str: str, output_file: str = None) -> bool:
        """
        Produce Gitlab Code Quality Reportoutput from input JSON string
        :param json_str: input JSON string
        :param output_file: Output file (optional)
        :return: True if successful, False otherwise
        """
        if not json_str:
            self.print_stderr('ERROR: No JSON string provided to parse.')
            return False
        try:
            data = json.loads(json_str)
        except Exception as e:
            self.print_stderr(f'ERROR: Problem parsing input JSON: {e}')
            return False
        return self._produce_from_json(data, output_file)


    def produce_from_file(self, json_file: str, output_file: str = None) -> bool:
        """
        Parse plain/raw input JSON file and produce GitLab Code Quality JSON output
        :param json_file:
        :param output_file:
        :return: True if successful, False otherwise
        """
        if not json_file:
            self.print_stderr('ERROR: No JSON file provided to parse.')
            return False
        if not os.path.isfile(json_file):
            self.print_stderr(f'ERROR: JSON file does not exist or is not a file: {json_file}')
            return False
        with open(json_file, 'r') as f:
            success = self._produce_from_str(f.read(), output_file)
        return success
