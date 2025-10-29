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
from typing import List

from ...policy_check.policy_check import PolicyCheck, PolicyOutput, PolicyStatus
from ...utils.markdown_utils import generate_jira_table, generate_table
from ...utils.scan_result_processor import ScanResultProcessor


@dataclass
class License:
    spdxid: str
    copyleft: bool
    url: str

@dataclass
class Component:
    purl: str
    version: str
    licenses: List[License]
    status: str

class UndeclaredComponent(PolicyCheck[Component]):
    """
    SCANOSS UndeclaredComponent class
    Inspects for undeclared components
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
        sbom_format: str = 'settings'
    ):
        """
        Initialize the UndeclaredComponent class.

        :param debug: Enable debug mode
        :param trace: Enable trace mode (default True)
        :param quiet: Enable quiet mode
        :param filepath: Path to the file containing component data
        :param format_type: Output format ('json' or 'md')
        :param status: Path to save status output
        :param output: Path to save detailed output
        :param sbom_format: Sbom format for status output (default 'settings')
        """
        super().__init__(
            debug, trace, quiet, format_type, status, name='Undeclared Components Policy', output=output
        )
        self.filepath = filepath
        self.output = output
        self.status = status
        self.sbom_format = sbom_format
        self.results_processor = ScanResultProcessor(self.debug, self.trace, self.quiet, self.filepath)


    def _get_undeclared_components(self, components: list[Component]) -> list or None:
        """
        Filter the components list to include only undeclared components.

        :param components: List of all components
        :return: List of undeclared components
        """
        if components is None:
            self.print_debug('WARNING: No components provided!')
            return None
        undeclared_components = []
        for component in components:
            if component['status'] == 'pending':
                # Remove unused keys
                del component['count']
                del component['declared']
                del component['undeclared']
                for lic in component['licenses']:
                        lic.pop('count', None)  # None is default value if key doesn't exist
                        lic.pop('source', None) # None is default value if key doesn't exist
                undeclared_components.append(component)
        # end component loop
        return undeclared_components

    def _get_jira_summary(self, components: list[Component]) -> str:
        """
        Get a summary of the undeclared components.

        :param components: List of all components
        :return: Component summary markdown
        """

        """
        Get a summary of the undeclared components.

        :param components: List of all components
        :return: Component summary markdown
        """
        if len(components) > 0:
            json_content = json.dumps(self._generate_scanoss_file(components), indent=2)

            if self.sbom_format == 'settings':
                return (
                    f'{len(components)} undeclared component(s) were found.\n'
                    f'Add the following snippet into your `scanoss.json` file\n'
                    f'{{code:json}}\n'
                    f'{json_content}\n'
                    f'{{code}}\n'
                )
            else:
                return (
                    f'{len(components)} undeclared component(s) were found.\n'
                    f'Add the following snippet into your `sbom.json` file\n'
                    f'{{code:json}}\n'
                    f'{json_content}\n'
                    f'{{code}}\n'
                )
        return f'{len(components)} undeclared component(s) were found.\\n'

    def _get_summary(self, components: list) -> str:
        """
        Get a summary of the undeclared components.

        :param components: List of all components
        :return: Component summary markdown
        """
        summary = f'{len(components)} undeclared component(s) were found.\n'
        if len(components) > 0:
            if self.sbom_format == 'settings':
                summary += (
                    f'Add the following snippet into your `scanoss.json` file\n'
                    f'\n```json\n{json.dumps(self._generate_scanoss_file(components), indent=2)}\n```\n'
                )
            else:
                summary += (
                    f'Add the following snippet into your `sbom.json` file\n'
                    f'\n```json\n{json.dumps(self._generate_sbom_file(components), indent=2)}\n```\n'
                )

        return summary

    def _json(self, components: list[Component]) -> PolicyOutput:
        """
        Format the undeclared components as JSON.

        :param components: List of undeclared components
        :return: Dictionary with formatted JSON details and summary
        """
        # Use component grouped by licenses to generate the summary
        component_licenses = self.results_processor.group_components_by_license(components)
        details = {}
        if len(components) > 0:
            details = {'components': components}
        return PolicyOutput(
            details=f'{json.dumps(details, indent=2)}\n',
            summary=self._get_summary(component_licenses)
        )

    def _markdown(self, components: list[Component]) -> PolicyOutput:
        """
        Format the undeclared components as Markdown.

        :param components: List of undeclared components
        :return: Dictionary with formatted Markdown details and summary
        """
        headers = ['Component', 'License']
        rows = []
        # TODO look at using SpdxLite license name lookup method
        component_licenses = self.results_processor.group_components_by_license(components)
        for component in component_licenses:
            rows.append([component.get('purl'), component.get('spdxid')])
        return PolicyOutput(
            details= f'### Undeclared components\n{generate_table(headers, rows)}\n',
            summary= self._get_summary(component_licenses),
        )

    def _jira_markdown(self, components: list) -> PolicyOutput:
        """
        Format the undeclared components as Markdown.

        :param components: List of undeclared components
        :return: Dictionary with formatted Markdown details and summary
        """
        headers = ['Component', 'License']
        rows = []
        # TODO look at using SpdxLite license name lookup method
        component_licenses = self.results_processor.group_components_by_license(components)
        for component in component_licenses:
            rows.append([component.get('purl'), component.get('spdxid')])
        return PolicyOutput(
            details= f'{generate_jira_table(headers, rows)}',
            summary= self._get_jira_summary(component_licenses),
        )

    def _get_unique_components(self, components: list) -> list:
        """
        Generate a list of unique components.

        :param components: List of undeclared components
        :return: list of unique components
        """
        unique_components = {}
        if components is None:
            self.print_stderr('WARNING: No components provided!')
            return []

        for component in components:
            unique_components[component['purl']] = {'purl': component['purl']}
        return list(unique_components.values())

    def _generate_scanoss_file(self, components: list) -> dict:
        """
        Generate a list of PURLs for the scanoss.json file.

        :param components: List of undeclared components
        :return: scanoss.json Dictionary
        """
        scanoss_settings = {
            'bom': {
                'include': self._get_unique_components(components),
            }
        }

        return scanoss_settings

    def _generate_sbom_file(self, components: list) -> dict:
        """
        Generate a list of PURLs for the SBOM file.

        :param components: List of undeclared components
        :return: SBOM Dictionary with components
        """
        sbom = {
            'components': self._get_unique_components(components),
        }

        return sbom

    def _get_components(self):
        """
        Extract and process components from file results only.

        This method performs the following steps:
        1. Validates if `self.results` is loaded. Returns `None` if not loaded.
        2. Extracts file and snippet components into a dictionary.
        3. Converts the components dictionary into a list of components.
        4. Processes the licenses for each component by converting them into a list.

        :return: A list of processed components with their licenses, or `None` if `self.results` is not set.
        """
        if self.results_processor.get_results() is None:
            return None
        components: dict = {}
        # Extract file and snippet components
        components = self.results_processor.get_components_data(components)
        # Convert to list and process licenses
        return self.results_processor.convert_components_to_list(components)

    def run(self):
        """
        Run the undeclared component inspection process.

        This method performs the following steps:
        1. Get all components
        2. Filter undeclared components
        3. Format the results
        4. Save the output to files if required

        :return: Dictionary containing the inspection results
        """
        self._debug()
        components = self._get_components()
        if components is None:
            return PolicyStatus.ERROR.value, {}
        # Get an undeclared component summary (if any)
        undeclared_components = self._get_undeclared_components(components)
        if undeclared_components is None:
            return PolicyStatus.ERROR.value, {}
        self.print_debug(f'Undeclared components: {undeclared_components}')
        # Format the results and save to files if required
        return self._generate_formatter_report(undeclared_components)
#
# End of UndeclaredComponent Class
#
