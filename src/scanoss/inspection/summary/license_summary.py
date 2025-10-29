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


class LicenseSummary(ScanossBase):
    """
       SCANOSS LicenseSummary class
       Inspects results and generates comprehensive license summaries from detected components.

       This class processes component scan results to extract, validate, and aggregate license
       information, providing detailed summaries including copyleft analysis and license statistics.
       """

    # Define required license fields as class constants
    REQUIRED_LICENSE_FIELDS = ['spdxid', 'url', 'copyleft', 'source']

    def __init__( # noqa: PLR0913
        self,
        debug: bool = False,
        trace: bool = False,
        quiet: bool = False,
        filepath: str = None,
        status: str = None,
        output: str = None,
        include: str = None,
        exclude: str = None,
        explicit: str = None,
    ):
        """
        Initialize the LicenseSummary class.

        :param debug: Enable debug mode
        :param trace: Enable trace mode
        :param quiet: Enable quiet mode
        :param filepath: Path to the file containing component data
        :param output: Path to save detailed output
        :param include: Licenses to include in the analysis
        :param exclude: Licenses to exclude from the analysis
        :param explicit: Explicitly defined licenses
        """
        super().__init__(debug=debug, trace=trace, quiet=quiet)
        self.results_processor = ScanResultProcessor(debug, trace, quiet, filepath, include, exclude, explicit)
        self.filepath = filepath
        self.output = output
        self.status = status
        self.include = include
        self.exclude = exclude
        self.explicit = explicit

    def _json(self, data: dict[str,Any]) -> dict[str, Any]:
        """
        Format license summary data as JSON.

        This method is intended to return the license summary data in JSON structure
        for serialization. The data should include license information with copyleft
        analysis and license statistics.

        :param data: List of license summary items to format
        :return: Dictionary containing license summary information including:
                 - licenses: List of detected licenses with SPDX IDs, URLs, and copyleft status
                 - detectedLicenses: Total number of unique licenses
                 - detectedLicensesWithCopyleft: Count of licenses marked as copyleft
        """
        return data

    def _markdown(self, data: list[T]) -> dict[str, Any]:
        """
        Format license summary data as Markdown (not yet implemented).

        This method is intended to convert license summary data into a human-readable
        Markdown format with tables and formatted sections.

        :param data: List of license summary items to format
        :return: Dictionary containing formatted Markdown output
        """
        pass

    def _jira_markdown(self, data: list[T]) -> dict[str, Any]:
        """
        Format license summary data as Jira-flavored Markdown (not yet implemented).

        This method is intended to convert license summary data into Jira-compatible
        Markdown format, which may include Jira-specific syntax for tables and formatting.

        :param data: List of license summary items to format
        :return: Dictionary containing Jira-formatted Markdown output
        """
        pass


    def _get_licenses_summary_from_components(self, components: list)-> dict:
        """
        Get a license summary from detected components.

        :param components: List of all components
        :return: Dict with license summary information
        """
        # A component is considered unique by its combination of PURL (Package URL) and license
        component_licenses = self.results_processor.group_components_by_license(components)
        license_component_count = {}
        # Count license per component
        for lic in component_licenses:
            if lic['spdxid'] not in license_component_count:
                license_component_count[lic['spdxid']] = 1
            else:
                license_component_count[lic['spdxid']] += 1
        licenses:dict = {}
        for comp_lic in component_licenses:
            spdxid = comp_lic.get("spdxid")
            url = comp_lic.get("url")
            copyleft = comp_lic.get("copyleft")
            if spdxid not in licenses:
                licenses[spdxid] = {
                    'spdxid': spdxid,
                    'url': url,
                    'copyleft': copyleft,
                    'componentCount': license_component_count.get(spdxid, 0), # Append component count to license
                }
            ## End for loop licenses
        ## End for loop components
        detected_licenses = list(licenses.values())
        licenses_with_copyleft = [lic for lic in detected_licenses if lic['copyleft']]
        return {
                 'licenses': detected_licenses,
                 'detectedLicenses': len(detected_licenses), # Count unique licenses. SPDXID is considered unique
                 'detectedLicensesWithCopyleft': len(licenses_with_copyleft),
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
        self.results_processor.get_dependencies_data(components)
        return self.results_processor.convert_components_to_list(components)

    def _format(self, license_summary) -> str:
        # TODO: Implement formatter to support dynamic outputs
        json_data = self._json(license_summary)
        return json.dumps(json_data, indent=2)

    def run(self):
        components = self._get_components()
        license_summary = self._get_licenses_summary_from_components(components)
        output = self._format(license_summary)
        self.print_to_file_or_stdout(output, self.output)
        return license_summary
#
# End of LicenseSummary Class
#