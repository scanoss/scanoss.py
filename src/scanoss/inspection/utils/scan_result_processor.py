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

from enum import Enum
from typing import Any, Dict, TypeVar

from ...scanossbase import ScanossBase
from ..utils.file_utils import load_json_file
from ..utils.license_utils import LicenseUtil


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

T = TypeVar('T')
class ScanResultProcessor(ScanossBase):
    """
    A utility class for processing and transforming scan results.

    This class provides functionality for processing scan results, including methods for
    loading, parsing, extracting, and aggregating component and license data from scan results.
    It serves as a shared data processing layer used by both policy checks and summary generators.

    Inherits from:
        ScanossBase: A base class providing common functionality for SCANOSS-related operations.
    """

    def __init__( # noqa: PLR0913
        self,
        debug: bool = False,
        trace: bool = False,
        quiet: bool = False,
        result_file_path: str = None,
        include: str = None,
        exclude: str = None,
        explicit: str = None,
        license_sources: list = None,
    ):
        super().__init__(debug, trace, quiet)
        self.result_file_path = result_file_path
        self.license_util = LicenseUtil()
        self.license_util.init(include, exclude, explicit)
        self.license_sources = license_sources
        self.results = self._load_input_file()

    def get_results(self) -> Dict[str, Any]:
        return self.results

    def _append_component(self, components: Dict[str, Any], new_component: Dict[str, Any]) -> Dict[str, Any]:
        """
          Append a new component to the component dictionary.

          This function creates a new entry in the component dictionary for the given component,
          initializing all required counters:
          - count: Total occurrences of this component (used by both license and component summaries)
          - declared: Number of times this component is marked as 'identified' (used by component summary)
          - undeclared: Number of times this component is marked as 'pending' (used by component summary)

          Each component also contains a 'licenses' dictionary where each license entry tracks:
          - count: Number of times this license appears for this component (used by license summary)

          Args:
              components: The existing dictionary of components
              new_component: The new component to be added
          Returns:
              The updated components dictionary
          """
        match_id = new_component.get('id')
        # Determine the component key and purl based on component type
        if match_id in [ComponentID.FILE.value, ComponentID.SNIPPET.value]:
            purl = new_component['purl'][0]  # Take the first purl for these component types
        else:
            purl = new_component['purl']

        if not purl:
            self.print_debug(f'WARNING: _append_component: No purl found for new component: {new_component}')
            return components

        component_key = f'{purl}@{new_component["version"]}'
        status = new_component.get('status')

        if component_key in components:
            # Component already exists, update component counters and try to append a new license
            self._update_component_counters(components[component_key], status)
            self._append_license_to_component(components, new_component, component_key)
            # Maintain 'pending' status - takes precedence over 'identified'
            if status == 'pending':
                components[component_key]['status'] = "pending"
            return components

        # Create a new component
        components[component_key] = {
            'purl': purl,
            'version': new_component['version'],
            'licenses': {},
            'status': status,
            'count': 1,
            'declared': 1 if status == 'identified' else 0,
            'undeclared': 1 if status == 'pending' else 0
        }

        ## Append license to component
        self._append_license_to_component(components, new_component, component_key)
        return components

    def _append_license_to_component(self,
         components: Dict[str, Any], new_component: Dict[str, Any], component_key: str) -> None:
        """
        Add or update licenses for an existing component.

        For each license in the component:
        - If the license already exists, increments its count
        - If it's a new license, adds it with an initial count of 1

        The license count is used by license_summary to track how many times each license appears
        across all components. This count contributes to:
        - Total number of licenses in the project
        - Number of copyleft licenses when the license is marked as copyleft

        Args:
            components: Dictionary containing all components
            new_component: Component whose licenses need to be processed
            component_key: purl + version of the component to be updated
        """
        # If not licenses are present
        if not new_component.get('licenses'):
            self.print_debug(f'WARNING: Results missing licenses. Skipping: {new_component}')
            return

        # Select licenses based on configuration (filtering or priority mode)
        selected_licenses = self._select_licenses(new_component['licenses'])

        # Process licenses for this component
        for license_item in selected_licenses:
            if license_item.get('name'):
                spdxid = license_item['name']
                source = license_item.get('source')
                if not source:
                    source = 'unknown'

                if spdxid in components[component_key]['licenses']:
                    # If license exists, increment counter
                    components[component_key]['licenses'][spdxid]['count'] += 1 # Increment counter for license
                else:
                    # If a license doesn't exist, create new entry
                    components[component_key]['licenses'][spdxid] = {
                        'spdxid': spdxid,
                        'copyleft': self.license_util.is_copyleft(spdxid),
                        'url': self.license_util.get_spdx_url(spdxid),
                        'source': source,
                        'count': 1, # Set counter to 1 on new license
                    }

    def _update_component_counters(self, component, status):
        """Update component counters based on status."""
        component['count'] += 1
        if status == 'identified':
            component['declared'] += 1
        else:
            component['undeclared'] += 1

    def get_components_data(self, components: Dict[str, Any]) -> Dict[str, Any]:
        """
           Extract and process file and snippet components from results.

           This method processes scan results to build or update component entries. For each component:

           Component Counters (used by ComponentSummary):
           - count: Incremented for each occurrence of the component
           - declared: Incremented when component status is 'identified'
           - undeclared: Incremented when component status is 'pending'

           License Tracking:
           - For new components, initializes license dictionary through _append_component
           - For existing components, updates license counters through _append_license_to_component
             which tracks the number of occurrences of each license

           Args:
               components: A dictionary containing the raw results of a component scan
           Returns:
               Updated components dictionary with file and snippet data
           """
        for component in self.results.values():
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
                    # Append component
                    components = self._append_component(components, c)

            # End component loop
        # End components loop
        return components

    def get_dependencies_data(self,components: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract and process dependency components from results.
        :param components: Existing components dictionary to update
        :return: Updated components dictionary with dependency data
        """
        for component in self.results.values():
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
                        version = dependency.get('version')
                        if not version:
                            self.print_debug(f'WARNING: Result missing version. Setting it to unknown: {c}')
                            version = 'unknown'
                            c['version'] = version  # Set an 'unknown' version to the current component

                        # Append component
                        components = self._append_component(components, dependency)

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
        try:
            return load_json_file(self.result_file_path)
        except Exception as e:
                self.print_stderr(f'ERROR: Problem parsing input JSON: {e}')
                return None

    def convert_components_to_list(self, components: dict):
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

    def _select_licenses(self, licenses_data):
        """
        Select licenses based on configuration.

        Two modes:
        - Filtering mode: If license_sources specified, filter to those sources
        - Priority mode: Otherwise, use original priority-based selection

        Args:
            licenses_data: List of license dictionaries

        Returns:
            Filtered list of licenses based on configuration
        """
        # Filtering mode, when license_sources is explicitly provided
        if self.license_sources:
            sources_to_include = set(self.license_sources) | {'unknown'}
            return [lic for lic in licenses_data
                    if lic.get('source') in sources_to_include or lic.get('source') is None]

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

    def group_components_by_license(self,components):
        """
        Groups components by their unique component-license pairs.

        This method processes a list of components and creates unique entries for each
        component-license combination. If a component has multiple licenses, it will create
        separate entries for each license.

        Args:
            components: A list of component dictionaries. Each component should have:
                - purl: Package URL identifying the component
                - licenses: List of license dictionaries, each containing:
                    - spdxid: SPDX identifier for the license (optional)

        Returns:
            list: A list of dictionaries, each containing:
                - purl: The component's package URL
                - license: The SPDX identifier of the license (or 'Unknown' if not provided)
        """
        component_licenses: dict = {}
        for component in components:
            purl = component.get('purl', '')
            status = component.get('status', '')
            licenses = component.get('licenses', [])

            # Component without license
            if not licenses:
                key = f'{purl}-unknown'
                component_licenses[key] = {
                    'purl': purl,
                    'spdxid': 'unknown',
                    'status': status,
                    'copyleft': False,
                    'url': '-',
                }
                continue

            # Iterate over licenses component licenses
            for lic in licenses:
                spdxid = lic.get('spdxid', 'unknown')
                if spdxid not in component_licenses:
                    key = f'{purl}-{spdxid}'
                    component_licenses[key] = {
                        'purl': purl,
                        'spdxid': spdxid,
                        'status': status,
                        'copyleft': lic['copyleft'],
                        'url': lic['url'],
                    }
        return list(component_licenses.values())


#
# End of ScanResultProcessor Class
#