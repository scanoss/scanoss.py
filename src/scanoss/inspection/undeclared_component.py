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
from typing import Dict, Any
from .policy_check import PolicyCheck, PolicyStatus


class UndeclaredComponent(PolicyCheck):
    """
    SCANOSS UndeclaredComponent class
    Inspects for undeclared components
    """

    def __init__(
        self,
        debug: bool = False,
        trace: bool = True,
        quiet: bool = False,
        filepath: str = None,
        format_type: str = 'json',
        status: str = None,
        output: str = None,
        sbom_format: str = 'settings',
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
            debug, trace, quiet, filepath, format_type, status, output, name='Undeclared Components Policy'
        )
        self.filepath = filepath
        self.format = format
        self.output = output
        self.status = status
        self.sbom_format = sbom_format

    def _get_undeclared_component(self, components: list) -> list or None:
        """
        Filter the components list to include only undeclared components.

        :param components: List of all components
        :return: List of undeclared components
        """
        if components is None:
            self.print_debug(f'WARNING: No components provided!')
            return None
        undeclared_components = []
        for component in components:
            if component['status'] == 'pending':
                del component['status']
                undeclared_components.append(component)
        # end component loop
        return undeclared_components

    def _get_jira_summary(self, components: list) -> str:
        """
        Get a summary of the undeclared components.

        :param components: List of all components
        :return: Component summary markdown
        """
        if len(components) > 0:
            if self.sbom_format == 'settings':
                json_str = (
                    json.dumps(self._generate_scanoss_file(components), indent=2)
                    .replace('\n', '\\n')
                    .replace('"', '\\"')
                )
                return f'{len(components)} undeclared component(s) were found.\nAdd the following snippet into your `scanoss.json` file\n{{code:json}}\n{json.dumps(self._generate_scanoss_file(components), indent=2)}\n{{code}}\n'
            else:
                json_str = (
                    json.dumps(self._generate_scanoss_file(components), indent=2)
                    .replace('\n', '\\n')
                    .replace('"', '\\"')
                )
                return f'{len(components)} undeclared component(s) were found.\nAdd the following snippet into your `sbom.json` file\n{{code:json}}\n{json.dumps(self._generate_scanoss_file(components), indent=2)}\n{{code}}\n'

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

    def _json(self, components: list) -> Dict[str, Any]:
        """
        Format the undeclared components as JSON.

        :param components: List of undeclared components
        :return: Dictionary with formatted JSON details and summary
        """
        details = {}
        if len(components) > 0:
            details = {'components': components}
        return {
            'details': f'{json.dumps(details, indent=2)}\n',
            'summary': self._get_summary(components),
        }

    def _markdown(self, components: list) -> Dict[str, Any]:
        """
        Format the undeclared components as Markdown.

        :param components: List of undeclared components
        :return: Dictionary with formatted Markdown details and summary
        """
        headers = ['Component', 'Version', 'License']
        rows: [[]] = []
        # TODO look at using SpdxLite license name lookup method
        for component in components:
            licenses = ' - '.join(lic.get('spdxid', 'Unknown') for lic in component['licenses'])
            rows.append([component['purl'], component['version'], licenses])
        return {
            'details': f'### Undeclared components\n{self.generate_table(headers, rows)}\n',
            'summary': self._get_summary(components),
        }

    def _jira_markdown(self, components: list) -> Dict[str, Any]:
        """
        Format the undeclared components as Markdown.

        :param components: List of undeclared components
        :return: Dictionary with formatted Markdown details and summary
        """
        headers = ['Component', 'Version', 'License']
        rows: [[]] = []
        # TODO look at using SpdxLite license name lookup method
        for component in components:
            licenses = ' - '.join(lic.get('spdxid', 'Unknown') for lic in component['licenses'])
            rows.append([component['purl'], component['version'], licenses])
        return {
            'details': f'{self.generate_jira_table(headers, rows)}',
            'summary': self._get_jira_summary(components),
        }

    def _get_unique_components(self, components: list) -> list:
        """
        Generate a list of unique components.

        :param components: List of undeclared components
        :return: list of unique components
        """
        unique_components = {}
        if components is None:
            self.print_stderr(f'WARNING: No components provided!')
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
        # Get undeclared component summary (if any)
        undeclared_components = self._get_undeclared_component(components)
        if undeclared_components is None:
            return PolicyStatus.ERROR.value, {}
        self.print_debug(f'Undeclared components: {undeclared_components}')
        formatter = self._get_formatter()
        if formatter is None:
            return PolicyStatus.ERROR.value, {}
        results = formatter(undeclared_components)
        # Output the results
        self.print_to_file_or_stdout(results['details'], self.output)
        self.print_to_file_or_stderr(results['summary'], self.status)
        # Determine if the filter found results or not
        if len(undeclared_components) <= 0:
            return PolicyStatus.FAIL.value, results
        return PolicyStatus.SUCCESS.value, results


#
# End of UndeclaredComponent Class
#
