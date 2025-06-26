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

from abc import abstractmethod
from enum import Enum
from typing import Any, Callable, Dict, List

from .inspect_base import InspectBase
from .utils.license_utils import LicenseUtil


class PolicyStatus(Enum):
    """
    Enumeration representing the status of a policy check.

    Attributes:
        SUCCESS (int): Indicates that the policy check passed successfully (value: 0).
        FAIL (int): Indicates that the policy check failed (value: 1).
        ERROR (int): Indicates that an error occurred during the policy check (value: 2).
    """

    SUCCESS = 0
    FAIL = 1
    ERROR = 2
#
# End of PolicyStatus Class
#

class PolicyCheck(InspectBase):
    """
    A base class for implementing various software policy checks.

    This class provides a framework for policy checking, including methods for
    processing components, generating output in different formats.

    Attributes:
        VALID_FORMATS (set): A set of valid output formats ('md', 'json').

    Inherits from:
        InspectBase: A base class providing common functionality for SCANOSS-related operations.
    """
    VALID_FORMATS = {'md', 'json', 'jira_md'}
    def __init__(  # noqa: PLR0913
            self,
            debug: bool = False,
            trace: bool = False,
            quiet: bool = False,
            filepath: str = None,
            format_type: str = None,
            status: str = None,
            output: str = None,
            name: str = None,
    ):
        super().__init__(debug, trace, quiet, filepath, output)
        self.license_util = LicenseUtil()
        self.filepath = filepath
        self.name = name
        self.format_type = format_type
        self.status = status
        self.results = self._load_input_file()

    @abstractmethod
    def run(self):
        """
        Execute the policy check process.

        This abstract method should be implemented by subclasses to perform specific
        policy checks. The general structure of this method typically includes:
        1. Retrieving components
        2. Filtering components based on specific criteria
        3. Formatting the results
        4. Saving the output to files if required

        :return: A tuple containing:
                 - First element: PolicyStatus enum value (SUCCESS, FAIL, or ERROR)
                 - Second element: Dictionary containing the inspection results
        """
        pass

    @abstractmethod
    def _json(self, components: list) -> Dict[str, Any]:
        """
        Format the policy checks results as JSON.
        This method should be implemented by subclasses to create a Markdown representation
        of the policy check results.

        :param components: List of components to be formatted.
        :return: A dictionary containing two keys:
                 - 'details': A JSON-formatted string with the full list of components
                 - 'summary': A string summarizing the number of components found
        """
        pass

    @abstractmethod
    def _markdown(self, components: list) -> Dict[str, Any]:
        """
        Generate Markdown output for the policy check results.

        This method should be implemented by subclasses to create a Markdown representation
        of the policy check results.

        :param components: List of components to be included in the output.
        :return: A dictionary representing the Markdown output.
        """
        pass

    @abstractmethod
    def _jira_markdown(self, components: list) -> Dict[str, Any]:
        """
        Generate Markdown output for the policy check results.

        This method should be implemented by subclasses to create a Markdown representation
        of the policy check results.

        :param components: List of components to be included in the output.
        :return: A dictionary representing the Markdown output.
        """
        pass

    def generate_table(self, headers, rows, centered_columns=None):
        """
        Generate a Markdown table.

        :param headers: List of headers for the table.
        :param rows: List of rows for the table.
        :param centered_columns: List of column indices to be centered.
        :return: A string representing the Markdown table.
        """
        col_sep = ' | '
        centered_column_set = set(centered_columns or [])
        if headers is None:
            self.print_stderr('ERROR: Header are no set')
            return None

        # Decide which separator to use
        def create_separator(index):
            if centered_columns is None:
                return '-'
            return ':-:' if index in centered_column_set else '-'

        # Build the row separator
        row_separator = col_sep + col_sep.join(create_separator(index) for index, _ in enumerate(headers)) + col_sep
        # build table rows
        table_rows = [col_sep + col_sep.join(headers) + col_sep, row_separator]
        table_rows.extend(col_sep + col_sep.join(row) + col_sep for row in rows)
        return '\n'.join(table_rows)

    def generate_jira_table(self, headers, rows, centered_columns=None):
        col_sep = '*|*'
        if headers is None:
            self.print_stderr('ERROR: Header are no set')
            return None

        table_header = '|*' + col_sep.join(headers) + '*|\n'
        table = table_header
        for row in rows:
            if len(headers) == len(row):
                table += '|' + '|'.join(row) + '|\n'

        return table

    def _get_formatter(self) -> Callable[[List[dict]], Dict[str, Any]] or None:
        """
        Get the appropriate formatter function based on the specified format.

        :return: Formatter function (either _json or _markdown)
        """
        valid_format = self._is_valid_format()
        if not valid_format:
            return None
        # a map of which format function to return
        function_map = {
            'json': self._json,
            'md': self._markdown,
            'jira_md': self._jira_markdown,
        }
        return function_map[self.format_type]

    def _debug(self):
        """
        Print debug information about the policy check.

        This method prints various attributes of the PolicyCheck instance for debugging purposes.
        """
        if self.debug:
            self.print_stderr(f'Policy: {self.name}')
            self.print_stderr(f'Format: {self.format_type}')
            self.print_stderr(f'Status: {self.status}')
            self.print_stderr(f'Output: {self.output}')
            self.print_stderr(f'Input: {self.filepath}')

    def _is_valid_format(self) -> bool:
        """
        Validate if the format specified is supported.

        This method checks if the format stored in format is one of the
        valid formats defined in self.VALID_FORMATS.

        :return: bool: True if the format is valid, False otherwise.
        """
        if self.format_type not in self.VALID_FORMATS:
            valid_formats_str = ', '.join(self.VALID_FORMATS)
            self.print_stderr(f'ERROR: Invalid format "{self.format_type}". Valid formats are: {valid_formats_str}')
            return False
        return True
#
# End of PolicyCheck Class
#