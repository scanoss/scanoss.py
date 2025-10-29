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

from abc import ABC, abstractmethod
from enum import Enum
from typing import Callable, Dict, Generic, List, NamedTuple, TypeVar

from ...scanossbase import ScanossBase
from ..utils.license_utils import LicenseUtil


class PolicyStatus(Enum):
    """
    Enumeration representing the status of a policy check.

    Attributes:
        POLICY_SUCCESS (int): Indicates that the policy check passed successfully (value: 0).
        POLICY_FAIL (int): Indicates that the policy check failed (value: 2).
        ERROR (int): Indicates that an error occurred during the policy check (value: 1).
    """
    POLICY_SUCCESS = 0
    POLICY_FAIL = 2
    ERROR = 1
#
# End of PolicyStatus Class
#

class PolicyOutput(NamedTuple):
    details: str
    summary: str

T = TypeVar('T')

class PolicyCheck(ScanossBase, Generic[T], ABC):
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
            format_type: str = None,
            status: str = None,
            name: str = None,
            output: str = None,
    ):
        super().__init__(debug, trace, quiet)
        self.license_util = LicenseUtil()
        self.name = name
        self.format_type = format_type
        self.status = status
        self.output = output

    @abstractmethod
    def run(self)-> tuple[int,PolicyOutput]:
        """
        Execute the policy check process.

        This abstract method should be implemented by subclasses to perform specific
        policy checks. The general structure of this method typically includes:
        1. Retrieving components
        2. Filtering components based on specific criteria
        3. Formatting the results
        4. Saving the output to files if required

        :return: A named tuple containing two elements:
                 - First element: PolicyStatus enum value (SUCCESS, FAIL, or ERROR)
                 - Second element: PolicyOutput A tuple containing the policy results.
        """
        pass

    @abstractmethod
    def _json(self, data: list[T]) -> PolicyOutput:
        """
        Format the policy checks results as JSON.
        This method should be implemented by subclasses to create a Markdown representation
        of the policy check results.

        :param data: List of data to be formatted.
        :return: A dictionary containing two keys:
                 - 'results': A JSON-formatted string with the full list of components
                 - 'summary': A string summarizing the number of components found
        """
        pass

    @abstractmethod
    def _markdown(self, data: list[T]) -> PolicyOutput:
        """
        Generate Markdown output for the policy check results.

        This method should be implemented by subclasses to create a Markdown representation
        of the policy check results.

        :param data: List of data to be included in the output.
        :return: A dictionary representing the Markdown output.
        """
        pass

    @abstractmethod
    def _jira_markdown(self, data: list[T]) -> PolicyOutput:
        """
        Generate Markdown output for the policy check results.

        This method should be implemented by subclasses to create a Markdown representation
        of the policy check results.

        :param data: List of data to be included in the output.
        :return: A dictionary representing the Markdown output.
        """
        pass

    def _get_formatter(self) -> Callable[[List[dict]], PolicyOutput]:
        """
        Get the appropriate formatter function based on the specified format.

        :return: Formatter function (either _json or _markdown)
        """
        valid_format = self._is_valid_format()
        if not valid_format:
            raise ValueError('Invalid format specified')
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

    def _generate_formatter_report(self, components: list[Dict]):
        """
        Generates a formatted report for a given component based on the defined formatter.

        Parameters:
            components (List[dict]): A list of dictionaries representing the components to be
            processed and formatted. Each dictionary contains detailed information that adheres
            to the format requirements for the specified formatter.

        Returns:
            Tuple[int, dict]: A tuple where the first element represents the policy status code
            and the second element is a dictionary containing formatted results information,
            typically with keys 'details' and 'summary'.

        Raises:
            KeyError: When a required key is missing from the provided component, causing the
            formatter to fail.
            ValueError: If an invalid component is passed and renders unable to process.
        """
        # Get a formatter for the output results
        formatter = self._get_formatter()
        if formatter is None:
            return PolicyStatus.ERROR.value, {}
        # Format the results
        policy_output = formatter(components)
        ## Save outputs if required
        self.print_to_file_or_stdout(policy_output.details, self.output)
        self.print_to_file_or_stderr(policy_output.summary, self.status)
        # Check to see if we have policy violations
        if len(components) > 0:
            return PolicyStatus.POLICY_FAIL.value, policy_output
        return PolicyStatus.POLICY_SUCCESS.value, policy_output
#
# End of PolicyCheck Class
#