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
from dataclasses import dataclass
from typing import Dict, List

from scanoss.constants import DEFAULT_COPYLEFT_LICENSE_SOURCES

from ...policy_check.policy_check import PolicyCheck, PolicyOutput, PolicyStatus
from ...utils.markdown_utils import generate_jira_table, generate_table
from ...utils.scan_result_processor import ScanResultProcessor


@dataclass
class License:
    spdxid: str
    copyleft: bool
    url: str
    source: str

@dataclass
class Component:
    purl: str
    version: str
    licenses: List[License]
    status: str

class Copyleft(PolicyCheck[Component]):
    """
    SCANOSS Copyleft class
    Inspects components for copyleft licenses
    """

    def __init__( # noqa: PLR0913
        self,
        debug: bool = False,
        trace: bool = False,
        quiet: bool = False,
        filepath: str = None,
        format_type: str = 'json',
        status: str = None,
        output: str = None,
        include: str = None,
        exclude: str = None,
        explicit: str = None,
        license_sources: list = None,
    ):
        """
        Initialise the Copyleft class.

        :param debug: Enable debug mode
        :param trace: Enable trace mode (default True)
        :param quiet: Enable quiet mode
        :param filepath: Path to the file containing component data
        :param format_type: Output format ('json' or 'md')
        :param status: Path to save the status output
        :param output: Path to save detailed output
        :param include: Licenses to include in the analysis
        :param exclude: Licenses to exclude from the analysis
        :param explicit: Explicitly defined licenses
        :param license_sources: List of license sources to check
        """
        super().__init__(
            debug, trace, quiet, format_type, status, name='Copyleft Policy', output=output
        )
        self.license_util.init(include, exclude, explicit)
        self.filepath = filepath
        self.output = output
        self.status = status
        self.license_sources = license_sources or DEFAULT_COPYLEFT_LICENSE_SOURCES
        self.results_processor = ScanResultProcessor(
            self.debug,
            self.trace,
            self.quiet,
            self.filepath,
            include,
            exclude,
            explicit,
            self.license_sources)

    def _json(self, components: list[Component]) -> PolicyOutput:
        """
        Format the components with copyleft licenses as JSON.

        :param components: List of components with copyleft licenses
        :return: Dictionary with formatted JSON details and summary
        """
        # A component is considered unique by its combination of PURL (Package URL) and license
        component_licenses = self.results_processor.group_components_by_license(components)
        details = {}
        if len(components) > 0:
            details = {'components': components}
        return PolicyOutput(
            details= f'{json.dumps(details, indent=2)}\n',
            summary= f'{len(component_licenses)} component(s) with copyleft licenses were found.\n',
        )

    def _markdown(self, components: list[Component]) -> PolicyOutput:
        """
        Format the components with copyleft licenses as Markdown.

        :param components: List of components with copyleft licenses
        :return: Dictionary with formatted Markdown details and summary
        """
        return self._md_summary_generator(components, generate_table)

    def _jira_markdown(self, components: list[Component]) -> PolicyOutput:
        """
        Format the components with copyleft licenses as Markdown.

        :param components: List of components with copyleft licenses
        :return: Dictionary with formatted Markdown details and summary
        """
        return self._md_summary_generator(components, generate_jira_table)

    def _md_summary_generator(self, components: list[Component], table_generator) -> PolicyOutput:
        """
        Generates a Markdown summary for components with a focus on copyleft licenses.

        This function processes a list of components and groups them by their licenses.
        For each group, the components are mapped with their license data and a tabular representation is created.
        The generated Markdown summary includes a detailed table and a summary overview.

        Parameters:
        components: list[Component]
            A list of Component objects to process for generating the summary.
        table_generator
            A callable function to generate tabular data for components.

        Returns:
            PolicyOutput
        """
        # A component is considered unique by its combination of PURL (Package URL) and license
        component_licenses = self.results_processor.group_components_by_license(components)
        headers = ['Component', 'License', 'URL', 'Copyleft']
        centered_columns = [1, 4]
        rows = []
        for comp_lic_item in component_licenses:
            row = [
                comp_lic_item['purl'],
                comp_lic_item['spdxid'],
                comp_lic_item['url'],
                'YES' if comp_lic_item['copyleft'] else 'NO',
            ]
            rows.append(row)
        # End license loop
        # End component loop
        return PolicyOutput(
            details= f'### Copyleft Licenses\n{table_generator(headers, rows, centered_columns)}',
            summary= f'{len(component_licenses)} component(s) with copyleft licenses were found.\n',
        )

    def _get_components_with_copyleft_licenses(self, components: list) -> list[Dict]:
        """
        Filter the components list to include only those with copyleft licenses.

        :param components: List of all components
        :return: List of components with copyleft licenses
        """
        filtered_components = []
        for component in components:
            copyleft_licenses = [lic for lic in component['licenses'] if lic['copyleft']]
            if copyleft_licenses:
                # Remove unused keys
                del component['count']
                del component['declared']
                del component['undeclared']
                filtered_component = component
                # Remove 'count' from each license using pop
                for lic in copyleft_licenses:
                    lic.pop('count', None)  # None is default value if key doesn't exist

                filtered_component['licenses'] = copyleft_licenses
                filtered_components.append(filtered_component)
        # End component loop
        self.print_debug(f'Copyleft components: {filtered_components}')
        return filtered_components

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
            return None
        components: dict = {}
        # Extract component and license data from file and dependency results. Both helpers mutate `components`
        self.results_processor.get_components_data(components)
        self.results_processor.get_dependencies_data(components)
        return self.results_processor.convert_components_to_list(components)

    def run(self):
        """
        Run the copyleft license inspection process.

        This method performs the following steps:
        1. Get all components
        2. Filter components with copyleft licenses
        3. Format the results
        4. Save the output to files if required

        :return: Dictionary containing the inspection results
        """
        self._debug()
        # Get the components from the results
        components = self._get_components()
        if components is None:
            return PolicyStatus.ERROR.value, {}
        # Get a list of copyleft components if they exist
        copyleft_components = self._get_components_with_copyleft_licenses(components)
        # Format the results and save to files if required
        return self._generate_formatter_report(copyleft_components)
#
# End of Copyleft Class
#
