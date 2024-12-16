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
import json
import os.path
from abc import abstractmethod
from enum import Enum
from typing import Callable, List, Dict, Any
from .utils.license_utils import LicenseUtil
from ..scanossbase import ScanossBase


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

class ComponentID(Enum):
    """
    Enumeration representing different types of software components.

    Attributes:
        FILE (str): Represents a file component (value: "file").
        SNIPPET (str): Represents a code snippet component (value: "snippet").
        DEPENDENCY (str): Represents a dependency component (value: "dependency").
    """
    FILE = "file"
    SNIPPET = "snippet"
    DEPENDENCY = "dependency"
#
# End of ComponentID Class
#

class PolicyCheck(ScanossBase):
    """
    A base class for implementing various software policy checks.

    This class provides a framework for policy checking, including methods for
    processing components, generating output in different formats.

    Attributes:
        VALID_FORMATS (set): A set of valid output formats ('md', 'json').

    Inherits from:
        ScanossBase: A base class providing common functionality for SCANOSS-related operations.
    """

    VALID_FORMATS = {'md', 'json'}

    def __init__(self, debug: bool = False, trace: bool = True, quiet: bool = False, filepath: str = None,
                 format_type: str = None, status: str = None, output: str = None, name: str = None):
        super().__init__(debug, trace, quiet)
        self.license_util = LicenseUtil()
        self.filepath = filepath
        self.name = name
        self.output = output
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

    def _append_component(self,components: Dict[str, Any], new_component: Dict[str, Any],
                           id: str, status: str) -> Dict[str, Any]:
        """
        Append a new component to the component's dictionary.

        This function creates a new entry in the components dictionary for the given component,
        or updates an existing entry if the component already exists. It also processes the
        licenses associated with the component.

        :param components: The existing dictionary of components
        :param new_component: The new component to be added or updated
        :param id: The new component ID
        :param status: The new component status
        :return: The updated components dictionary
        """

        # Determine the component key and purl based on component type
        if id in [ComponentID.FILE.value, ComponentID.SNIPPET.value]:
            purl = new_component['purl'][0]  # Take first purl for these component types
        else:
            purl = new_component['purl']

        component_key = f"{purl}@{new_component['version']}"
        components[component_key] = {
                'purl': purl,
                'version': new_component['version'],
                'licenses': {},
                'status': status,
        }

        if not new_component.get('licenses'):
            self.print_stderr(f'WARNING: Results missing licenses. Skipping.')
            return components
        # Process licenses for this component
        for l in new_component['licenses']:
            if l.get('name'):
                spdxid = l['name']
                components[component_key]['licenses'][spdxid] = {
                    'spdxid': spdxid,
                    'copyleft': self.license_util.is_copyleft(spdxid),
                    'url': self.license_util.get_spdx_url(spdxid),
                }
        return components

    def _get_components_from_results(self,results: Dict[str, Any]) -> list or None:
        """
            Process the results dictionary to extract and format component information.

            This function iterates through the results dictionary, identifying components from
            different sources (files, snippets, and dependencies). It consolidates this information
            into a list of unique components, each with its associated licenses and other details.

            :param results: A dictionary containing the raw results of a component scan
            :return: A list of dictionaries, each representing a unique component with its details
        """
        if results is None:
            self.print_stderr(f'ERROR: Results cannot be empty')
            return None
        components = {}
        for component in results.values():
            for c in component:
                component_id = c.get('id')
                if not component_id:
                    self.print_stderr(f'WARNING: Result missing id. Skipping.')
                    continue
                status = c.get('status')
                if not component_id:
                    self.print_stderr(f'WARNING: Result missing status. Skipping.')
                    continue
                if component_id in [ComponentID.FILE.value, ComponentID.SNIPPET.value]:
                    if not c.get('purl'):
                        self.print_stderr(f'WARNING: Result missing purl. Skipping.')
                        continue
                    if len(c.get('purl')) <= 0:
                        self.print_stderr(f'WARNING: Result missing purls. Skipping.')
                        continue
                    if not c.get('version'):
                        self.print_stderr(f'WARNING: Result missing version. Skipping.')
                        continue
                    component_key = f"{c['purl'][0]}@{c['version']}"
                    # Initialize or update the component entry
                    if component_key not in components:
                        components = self._append_component(components, c, component_id, status)

                if c['id'] == ComponentID.DEPENDENCY.value:
                    if c.get('dependencies') is None:
                        continue
                    for d in c['dependencies']:
                        if not d.get('purl'):
                            self.print_stderr(f'WARNING: Result missing purl. Skipping.')
                            continue
                        if len(d.get('purl')) <= 0:
                            self.print_stderr(f'WARNING: Result missing purls. Skipping.')
                            continue
                        if not d.get('version'):
                            self.print_stderr(f'WARNING: Result missing version. Skipping.')
                            continue
                        component_key = f"{d['purl']}@{d['version']}"
                        if component_key not in components:
                            components = self._append_component(components, d, component_id, status)
                    # End of dependencies loop
                # End if
            # End of component loop
        # End of results loop
        results = list(components.values())
        for component in results:
            component['licenses'] = list(component['licenses'].values())

        return results

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

    def _get_formatter(self)-> Callable[[List[dict]], Dict[str,Any]] or None:
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
            'md': self._markdown
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

    def _load_input_file(self):
        """
        Load the result.json file

          Returns:
              Dict[str, Any]: The parsed JSON data
          """
        if not os.path.exists(self.filepath):
            self.print_stderr(f'ERROR: The file "{self.filepath}" does not exist.')
            return None
        with open(self.filepath, "r") as jsonfile:
            try:
                return json.load(jsonfile)
            except Exception as e:
                self.print_stderr(f'ERROR: Problem parsing input JSON: {e}')
        return None

    def _get_components(self):
        """
        Retrieve and process components from the preloaded results.

        This method performs the following steps:
        1. Checks if the results have been previously loaded (self.results).
        2. Extracts and processes components from the loaded results.

        :return: A list of processed components, or None if an error occurred during any step.
                 Possible reasons for returning None include:
                 - Results not loaded (self.results is None)
                 - Failure to extract components from the results

        Note:
        - This method assumes that the results have been previously loaded and stored in self.results.
        - If results is None, the method returns None without performing any further operations.
        - The actual processing of components is delegated to the _get_components_from_results method.
        """
        if self.results is None:
            return None
        components = self._get_components_from_results(self.results)
        return components
#
# End of PolicyCheck Class
#
