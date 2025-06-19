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
from typing import Any, Dict

from .inspect_base import InspectBase


class LicenseSummary(InspectBase):
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
        trace: bool = True,
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
        :param trace: Enable trace mode (default True)
        :param quiet: Enable quiet mode
        :param filepath: Path to the file containing component data
        :param output: Path to save detailed output
        :param include: Licenses to include in the analysis
        :param exclude: Licenses to exclude from the analysis
        :param explicit: Explicitly defined licenses
        """
        super().__init__(debug, trace, quiet, filepath, output)
        self.license_util.init(include, exclude, explicit)
        self.filepath = filepath
        self.output = output
        self.status = status
        self.include = include
        self.exclude = exclude
        self.explicit = explicit

    def _validate_license(self, license_data: Dict[str, Any]) -> bool:
        """
        Validate that a license has all required fields.

        :param license_data: Dictionary containing license information
        :return: True if license is valid, False otherwise
        """
        for field in self.REQUIRED_LICENSE_FIELDS:
            value = license_data.get(field)
            if value is None:
                self.print_debug(f'WARNING: {field} is empty in license: {license_data}')
                return False
        return True

    def _append_license(self, licenses: dict, new_license) -> None:
        """Add or update a license in the licenses' dictionary."""
        spdxid = new_license.get("spdxid")
        url = new_license.get("url")
        copyleft = new_license.get("copyleft")
        if spdxid not in licenses:
            licenses[spdxid] = {
                'spdxid': spdxid,
                'url': url,
                'copyleft':copyleft,
                'count': new_license.get("count"),
            }
        else:
            licenses[spdxid]['count'] += new_license.get("count")

    def _get_licenses_summary_from_components(self, components: list)-> dict:
        """
        Get a license summary from detected components.

        :param components: List of all components
        :return: Dict with license summary information
        """
        licenses:dict = {}
        licenses_with_copyleft = 0
        total_licenses = 0
        for component in components:
            component_licenses =  component.get("licenses", [])
            for lic in component_licenses:
                if not self._validate_license(lic):
                    continue
                copyleft = lic.get("copyleft")
                ## Increment counters
                total_licenses += lic.get("count")
                if copyleft:
                    licenses_with_copyleft += lic.get("count")
                ## Add license
                self._append_license(licenses, lic)
            ## End for loop licenses
        ## End for loop components
        return {
                 'licenses': list(licenses.values()),
                 'total': total_licenses,
                 'copyleft': licenses_with_copyleft
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
        if self.results is None:
            return None

        components: dict = {}
        # Extract component and license data from file and dependency results. Both helpers mutate `components`
        self._get_components_data(self.results, components)
        self._get_dependencies_data(self.results, components)
        return self._convert_components_to_list(components)

    def run(self):
        components = self._get_components()
        license_summary = self._get_licenses_summary_from_components(components)
        self.print_to_file_or_stdout(json.dumps(license_summary, indent=2), self.output)
        return license_summary
#
# End of LicenseSummary Class
#