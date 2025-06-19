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
import os.path
from abc import abstractmethod
from enum import Enum
from typing import Any, Dict

from ..scanossbase import ScanossBase
from .utils.license_utils import LicenseUtil


class ComponentID(Enum):
    """
    Enumeration representing different types of software components.

    Attributes:
        FILE (str): Represents a file component (value: "file").
        SNIPPET (str): Represents a code snippet component (value: "snippet").
        DEPENDENCY (str): Represents a dependency component (value: "dependency").
    """

    FILE = 'file'
    SNIPPET = 'snippet'
    DEPENDENCY = 'dependency'


#
# End of ComponentID Class
#


class InspectBase(ScanossBase):
    """
    A base class to perform inspections over scan results.

    This class provides a basic for scan results inspection, including methods for
    processing scan results components and licenses.

    Inherits from:
        ScanossBase: A base class providing common functionality for SCANOSS-related operations.
    """

    def __init__( # noqa: PLR0913
        self,
        debug: bool = False,
        trace: bool = True,
        quiet: bool = False,
        filepath: str = None,
        output: str = None,
    ):
        super().__init__(debug, trace, quiet)
        self.license_util = LicenseUtil()
        self.filepath = filepath
        self.output = output
        self.results = self._load_input_file()

    @abstractmethod
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
        - Implementations must extract components (e.g. via `_get_components_data`,
          `_get_dependencies_data`, or other helpers).
        - If `self.results` is `None`, simply return `None`.
        """
    pass

    def _append_component(
        self, components: Dict[str, Any], new_component: Dict[str, Any], id: str, status: str
    ) -> Dict[str, Any]:
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
            purl = new_component['purl'][0]  # Take the first purl for these component types
        else:
            purl = new_component['purl']

        if not purl:
            self.print_debug(f'WARNING: _append_component: No purl found for new component: {new_component}')
            return components

        component_key = f'{purl}@{new_component["version"]}'
        components[component_key] = {
            'purl': purl,
            'version': new_component['version'],
            'licenses': {},
            'status': status,
        }
        if not new_component.get('licenses'):
            self.print_debug(f'WARNING: Results missing licenses. Skipping: {new_component}')
            return components


        licenses_order_by_source_priority = self._get_licenses_order_by_source_priority(new_component['licenses'])
        # Process licenses for this component
        for license_item in licenses_order_by_source_priority:
            if license_item.get('name'):
                spdxid = license_item['name']
                source = license_item.get('source')
                if not source:
                    source = 'unknown'
                components[component_key]['licenses'][spdxid] = {
                    'spdxid': spdxid,
                    'copyleft': self.license_util.is_copyleft(spdxid),
                    'url': self.license_util.get_spdx_url(spdxid),
                    'source': source,
                }
        return components

    def _get_components_data(self, results: Dict[str, Any], components: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract and process file and snippet components from results.

        :param results: A dictionary containing the raw results of a component scan
        :param components: Existing components dictionary to update
        :return: Updated components dictionary with file and snippet data
        """
        for component in results.values():
            for c in component:
                component_id = c.get('id')
                if not component_id:
                    self.print_debug(f'WARNING: Result missing id. Skipping: {c}')
                    continue
                ## Skip dependency
                if component_id == ComponentID.DEPENDENCY.value:
                    continue
                status = c.get('status')
                if not status:
                    self.print_debug(f'WARNING: Result missing status. Skipping: {c}')
                    continue
                if component_id in [ComponentID.FILE.value, ComponentID.SNIPPET.value]:
                    if not c.get('purl'):
                        self.print_debug(f'WARNING: Result missing purl. Skipping: {c}')
                        continue
                    if len(c.get('purl')) <= 0:
                        self.print_debug(f'WARNING: Result missing purls. Skipping: {c}')
                        continue
                    version = c.get('version')
                    if not version:
                        self.print_debug(f'WARNING: Result missing version. Setting it to unknown: {c}')
                        version = 'unknown'
                        c['version'] = version #If no version exists. Set 'unknown' version to current component
                    component_key = f'{c["purl"][0]}@{version}'
                    if component_key not in components:
                        components = self._append_component(components, c, component_id, status)
            # End component loop
        # End components loop
        return components

    def _get_dependencies_data(self, results: Dict[str, Any], components: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract and process dependency components from results.

        :param results: A dictionary containing the raw results of a component scan
        :param components: Existing components dictionary to update
        :return: Updated components dictionary with dependency data
        """
        for component in results.values():
            for c in component:
                component_id = c.get('id')
                if not component_id:
                    self.print_debug(f'WARNING: Result missing id. Skipping: {c}')
                    continue
                status = c.get('status')
                if not status:
                    self.print_debug(f'WARNING: Result missing status. Skipping: {c}')
                    continue
                if component_id == ComponentID.DEPENDENCY.value:
                    if c.get('dependencies') is None:
                        continue
                    for dependency in c['dependencies']:
                        if not dependency.get('purl'):
                            self.print_debug(f'WARNING: Dependency result missing purl. Skipping: {dependency}')
                            continue
                        version = c.get('version')
                        if not version:
                            self.print_debug(f'WARNING: Result missing version. Setting it to unknown: {c}')
                            version = 'unknown'
                            c['version'] = version  # If no version exists. Set 'unknown' version to current component
                        component_key = f'{dependency["purl"]}@{version}'
                        if component_key not in components:
                            components = self._append_component(components, dependency, component_id, status)
                    # End dependency loop
            # End component loop
        # End of result loop
        return components

    def _load_input_file(self):
        """
        Load the result.json file

          Returns:
              Dict[str, Any]: The parsed JSON data
        """
        if not os.path.exists(self.filepath):
            self.print_stderr(f'ERROR: The file "{self.filepath}" does not exist.')
            return None
        with open(self.filepath, 'r') as jsonfile:
            try:
                return json.load(jsonfile)
            except Exception as e:
                self.print_stderr(f'ERROR: Problem parsing input JSON: {e}')
        return None

    def _convert_components_to_list(self, components: dict):
        if components is None:
            self.print_debug(f'WARNING: Components is empty {self.results}')
            return None
        results_list = list(components.values())
        for component in results_list:
            licenses = component.get('licenses')
            if licenses is not None:
                component['licenses'] = list(licenses.values())
            else:
                self.print_debug(f'WARNING: Licenses missing for: {component}')
                component['licenses'] = []
        return results_list

    def _get_licenses_order_by_source_priority(self,licenses_data):
        """
        Select licenses based on source priority:
        1. component_declared (highest priority)
        2. license_file
        3. file_header
        4. scancode (lowest priority)

        If any high-priority source is found, return only licenses from that source.
        If none found, return all licenses.

        Returns: list with ordered licenses by source.
        """
        # Define priority order (highest to lowest)
        priority_sources = ['component_declared', 'license_file', 'file_header', 'scancode']

        # Group licenses by source
        licenses_by_source = {}
        for license_item in licenses_data:

            source = license_item.get('source', 'unknown')
            if source not in licenses_by_source:
                licenses_by_source[source] = {}

            license_name = license_item.get('name')
            if license_name:
                # Use license name as key, store full license object as value
                # If duplicate license names exist in same source, the last one wins
                licenses_by_source[source][license_name] = license_item

        # Find the highest priority source that has licenses
        for priority_source in priority_sources:
            if priority_source in licenses_by_source:
                self.print_trace(f'Choosing {priority_source} as source')
                return list(licenses_by_source[priority_source].values())

        # If no priority sources found, combine all licenses into a single list
        self.print_debug("No priority sources found, returning all licenses as list")
        return licenses_data


#
# End of PolicyCheck Class
#
