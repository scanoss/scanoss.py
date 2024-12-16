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

class Copyleft(PolicyCheck):
    """
    SCANOSS Copyleft class
    Inspects components for copyleft licenses
    """

    def __init__(self, debug: bool = False, trace: bool = True, quiet: bool = False, filepath: str = None,
                 format_type: str = 'json', status: str = None, output: str = None, include: str = None,
                 exclude: str = None, explicit: str = None):
        """
               Initialize the Copyleft class.

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
        """
        super().__init__(debug, trace, quiet, filepath, format_type, status, output, name='Copyleft Policy')
        self.license_util.init(include, exclude, explicit)
        self.filepath = filepath
        self.format = format
        self.output = output
        self.status = status
        self.include = include
        self.exclude = exclude
        self.explicit = explicit

    def _json(self, components: list) -> Dict[str, Any]:
        """
           Format the components with copyleft licenses as JSON.

           :param components: List of components with copyleft licenses
           :return: Dictionary with formatted JSON details and summary
        """
        details = {}
        if len(components) > 0:
            details = { 'components': components }
        return {
            'details':  f'{json.dumps(details, indent=2)}\n',
            'summary': f'{len(components)} component(s) with copyleft licenses were found.\n'
        }

    def _markdown(self, components: list) -> Dict[str,Any]:
        """
        Format the components with copyleft licenses as Markdown.

        :param components: List of components with copyleft licenses
        :return: Dictionary with formatted Markdown details and summary
        """
        headers = ['Component', 'Version', 'License', 'URL', 'Copyleft']
        centered_columns = [1, 4]
        rows: [[]]= []
        for component in components:
            for lic in component['licenses']:
                row = [
                    component['purl'],
                    component['version'],
                    lic['spdxid'],
                    lic['url'],
                    'YES' if lic['copyleft'] else 'NO'
                ]
                rows.append(row)
            # End license loop
        # End component loop
        return  {
            'details': f'### Copyleft licenses\n{self.generate_table(headers,rows,centered_columns)}\n',
            'summary' : f'{len(components)} component(s) with copyleft licenses were found.\n'
        }

    def _filter_components_with_copyleft_licenses(self, components: list) -> list:
        """
           Filter the components list to include only those with copyleft licenses.

           :param components: List of all components
           :return: List of components with copyleft licenses
        """
        filtered_components = []
        for component in components:
            copyleft_licenses = [lic for lic in component['licenses'] if lic['copyleft']]
            if copyleft_licenses:
                filtered_component = component
                filtered_component['licenses'] = copyleft_licenses
                del filtered_component['status']
                filtered_components.append(filtered_component)
        # End component loop
        self.print_debug(f'Copyleft components: {filtered_components}')
        return filtered_components

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
        copyleft_components = self._filter_components_with_copyleft_licenses(components)
        # Get a formatter for the output results
        formatter = self._get_formatter()
        if formatter is None:
            return PolicyStatus.ERROR.value, {}
        # Format the results
        results = formatter(copyleft_components)
        ## Save outputs if required
        self.print_to_file_or_stdout(results['details'], self.output)
        self.print_to_file_or_stderr(results['summary'], self.status)
        # Check to see if we have policy violations
        if len(copyleft_components) <= 0:
            return PolicyStatus.FAIL.value, results
        return PolicyStatus.SUCCESS.value, results
#
# End of Copyleft Class
#
