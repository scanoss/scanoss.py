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
        self.print_trace(f"GitLabQualityReport initialized with debug={debug}, trace={trace}, quiet={quiet}")


    def _get_code_quality(self, file_name: str, result: dict) -> CodeQuality or None:
        self.print_trace(f"_get_code_quality called for file: {file_name}")
        self.print_trace(f"Processing result: {result}")

        if not result.get('file_hash'):
            self.print_debug(f"Warning: no hash found for result: {result}")
            return None

        if result.get('id') == 'file':
            self.print_debug(f"Processing file match for: {file_name}")
            description = f"File match found in: {file_name}"
            code_quality = CodeQuality(
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
            self.print_trace(f"Created file CodeQuality object: {code_quality}")
            return code_quality

        if not result.get('lines'):
            self.print_debug(f"Warning: No lines found for result: {result}")
            return None
        lines = scanoss_scan_results_utils.get_lines(result.get('lines'))
        self.print_trace(f"Extracted lines: {lines}")
        if len(lines) == 0:
            self.print_debug(f"Warning: empty lines for result: {result}")
            return None
        end_line = lines[len(lines) - 1] if len(lines) > 1 else lines[0]
        description = f"Snippet found in: {file_name} - lines {lines[0]}-{end_line}"
        self.print_debug(f"Processing snippet match for: {file_name}, lines: {lines[0]}-{end_line}")
        code_quality = CodeQuality(
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
        self.print_trace(f"Created snippet CodeQuality object: {code_quality}")
        return code_quality

    def _write_output(self, data: list[CodeQuality], output_file: str = None) -> bool:
        """Write the Gitlab Code Quality Report to output."""
        self.print_trace(f"_write_output called with {len(data)} items, output_file: {output_file}")
        try:
            json_data = [item.to_dict() for item in data]
            self.print_trace(f"JSON data: {json_data}")
            file = open(output_file, 'w') if output_file else sys.stdout
            print(json.dumps(json_data, indent=2), file=file)
            if output_file:
                file.close()
                self.print_debug(f"Wrote output to file: {output_file}")
            else:
                self.print_debug("Wrote output to 'stdout'")
            return True
        except Exception as e:
            self.print_stderr(f'Error writing output: {str(e)}')
            return False

    def _produce_from_json(self, data: dict, output_file: str = None) -> bool:
        self.print_trace(f"_produce_from_json called with output_file: {output_file}")
        self.print_debug(f"Processing {len(data)} files from JSON data")
        code_quality = []
        for file_name, results in data.items():
            self.print_trace(f"Processing file: {file_name} with {len(results)} results")
            for result in results:
                if not result.get('id'):
                    self.print_debug(f"Warning: No ID found for result: {result}")
                    continue
                if result.get('id') != 'snippet' and result.get('id') != 'file':
                    self.print_debug(f"Skipping non-snippet/file match: {file_name}, id: '{result['id']}'")
                    continue
                code_quality_item = self._get_code_quality(file_name, result)
                if code_quality_item:
                    code_quality.append(code_quality_item)
                    self.print_trace(f"Added code quality item for {file_name}")
                else:
                    self.print_debug(f"Warning: No Code Quality found for result: {result}")
        self.print_debug(f"Generated {len(code_quality)} code quality items")
        self._write_output(data=code_quality,output_file=output_file)
        return True

    def _produce_from_str(self, json_str: str, output_file: str = None) -> bool:
        """
        Produce Gitlab Code Quality Report output from input JSON string
        :param json_str: input JSON string
        :param output_file: Output file (optional)
        :return: True if successful, False otherwise
        """
        self.print_trace(f"_produce_from_str called with output_file: {output_file}")
        if not json_str:
            self.print_stderr('ERROR: No JSON string provided to parse.')
            return False
        self.print_debug(f"Parsing JSON string of length: {len(json_str)}")
        try:
            data = json.loads(json_str)
            self.print_debug("Successfully parsed JSON data")
            self.print_trace(f"Parsed data structure: {type(data)}")
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
        self.print_trace(f"produce_from_file called with json_file: {json_file}, output_file: {output_file}")
        self.print_debug(f"Input JSON file: {json_file}, output_file: {output_file}")
        if not json_file:
            self.print_stderr('ERROR: No JSON file provided to parse.')
            return False
        if not os.path.isfile(json_file):
            self.print_stderr(f'ERROR: JSON file does not exist or is not a file: {json_file}')
            return False
        self.print_debug(f"Reading JSON file: {json_file}")
        with open(json_file, 'r') as f:
            json_content = f.read()
            success = self._produce_from_str(json_content, output_file)
        return success
