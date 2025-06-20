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

from .inspect_base import InspectBase


class ComponentSummary(InspectBase):
    def _get_component_summary_from_components(self, scan_components: list)-> dict:
        """
        Get a component summary from detected components.

        :param components: List of all components
        :return: Dict with license summary information
        """
        components: list = []
        undeclared_components = 0
        total_components = 0
        for component in scan_components:
            total_components += component['count']
            undeclared_components += component['undeclared']
            components.append({
                'purl': component['purl'],
                'version': component['version'],
                'count': component['count'],
                'undeclared': component['undeclared'],
                'declared': component['count'] - component['undeclared'],
            })
        ## End for loop components
        return {
            'components': components,
            'total': total_components,
            'undeclared': undeclared_components,
            'declared': total_components - undeclared_components,
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
        return self._convert_components_to_list(components)

    def run(self):
        components = self._get_components()
        component_summary = self._get_component_summary_from_components(components)
        self.print_to_file_or_stdout(json.dumps(component_summary, indent=2), self.output)
        return component_summary
#
# End of ComponentSummary Class
#