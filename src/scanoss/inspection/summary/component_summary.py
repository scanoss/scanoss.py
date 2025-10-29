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
from typing import Any

from ...scanossbase import ScanossBase
from ..policy_check.policy_check import T
from ..utils.scan_result_processor import ScanResultProcessor


class ComponentSummary(ScanossBase):

    def __init__( # noqa: PLR0913
        self,
        debug: bool = False,
        trace: bool = False,
        quiet: bool = False,
        filepath: str = None,
        format_type: str = 'json',
        output: str = None,
    ):
        """
        Initialize the ComponentSummary class.

        :param debug: Enable debug mode
        :param trace: Enable trace mode
        :param quiet: Enable quiet mode
        :param filepath: Path to the file containing component data
        :param format_type: Output format ('json' or 'md')
        """
        super().__init__(debug, trace, quiet)
        self.filepath = filepath
        self.output = output
        self.results_processor = ScanResultProcessor(debug, trace, quiet, filepath)


    def _json(self, data: dict[str,Any]) -> dict[str,Any]:
        """
        Format component summary data as JSON.

        This method returns the component summary data in its original JSON structure
        without any transformation. The data can be directly serialized to JSON format.

        :param data: Dictionary containing component summary information including:
                     - components: List of component-license pairs with status and metadata
                     - totalComponents: Total number of unique components
                     - undeclaredComponents: Number of components with 'pending' status
                     - declaredComponents: Number of components with 'identified' status
                     - totalFilesDetected: Total count of files where components were detected
                     - totalFilesUndeclared: Count of files with undeclared components
                     - totalFilesDeclared: Count of files with declared components
        :return: The same data dictionary, ready for JSON serialization
        """
        return data

    def _markdown(self, data: list[T]) -> dict[str, Any]:
        """
        Format component summary data as Markdown (not yet implemented).

        This method is intended to convert component summary data into a human-readable
        Markdown format with tables and formatted sections.

        :param data: List of component summary items to format
        :return: Dictionary containing formatted Markdown output
        """
        pass

    def _jira_markdown(self, data: list[T]) -> dict[str, Any]:
        """
        Format component summary data as Jira-flavored Markdown (not yet implemented).

        This method is intended to convert component summary data into Jira-compatible
        Markdown format, which may include Jira-specific syntax for tables and formatting.

        :param data: List of component summary items to format
        :return: Dictionary containing Jira-formatted Markdown output
        """
        pass

    def _get_component_summary_from_components(self, scan_components: list)-> dict:
        """
        Get a component summary from detected components.

        :param scan_components: List of all components
        :return: Dict with license summary information
        """
        # A component is considered unique by its combination of PURL (Package URL) and license
        component_licenses = self.results_processor.group_components_by_license(scan_components)
        total_components = len(component_licenses)
        # Get undeclared components
        undeclared_components = len([c for c in component_licenses if c['status'] == 'pending'])

        components: list = []
        total_undeclared_files = 0
        total_files_detected = 0
        for component in scan_components:
            total_files_detected += component['count']
            total_undeclared_files += component['undeclared']
            components.append({
                'purl': component['purl'],
                'version': component['version'],
                'count': component['count'],
                'undeclared': component['undeclared'],
                'declared': component['count'] - component['undeclared'],
            })
        ## End for loop components
        return {
            "components": component_licenses,
            'totalComponents': total_components,
            'undeclaredComponents': undeclared_components,
            'declaredComponents': total_components - undeclared_components,
            'totalFilesDetected': total_files_detected,
            'totalFilesUndeclared': total_undeclared_files,
            'totalFilesDeclared': total_files_detected - total_undeclared_files,
        }

    def _get_components(self):
        """
        Extract and process components from results and their dependencies.

        This method performs the following steps:
        1. Validates that `self.results` is loaded. Returns `None` if not.
        2. Extracts file, snippet, and dependency components into a dictionary.
        3. Converts components to a list and processes their licenses.

        :return: A list of processed components with license data, or `None` if `self.results` is not set.
        """
        if self.results_processor.get_results() is None:
            raise ValueError(f'Error: No results found in {self.filepath}')

        components: dict = {}
        # Extract component and license data from file and dependency results. Both helpers mutate `components`
        self.results_processor.get_components_data(components)
        return self.results_processor.convert_components_to_list(components)

    def _format(self, component_summary) -> str:
        # TODO: Implement formatter to support dynamic outputs
        json_data = self._json(component_summary)
        return json.dumps(json_data, indent=2)

    def run(self):
        components = self._get_components()
        component_summary = self._get_component_summary_from_components(components)
        output = self._format(component_summary)
        self.print_to_file_or_stdout(output, self.output)
        return component_summary
#
# End of ComponentSummary Class
#