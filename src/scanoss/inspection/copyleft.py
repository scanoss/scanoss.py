import json
import sys
from typing import Dict, Any, Callable, List
from scanoss.inspection.policy_check import PolicyCheck, PolicyStatus
from scanoss.inspection.utils.license_utils import license_util
from scanoss.inspection.utils.markdown_utils import generate_table


class Copyleft(PolicyCheck):
    """
    SCANOSS Copyleft class \n
    Inspects for copyleft licenses
    """

    def __init__(self, debug: bool = False, trace: bool = True, quiet: bool = False, filepath: str = None,
                 format: str = 'json', status: str = None, output: str = None, include: str = None, exclude: str = None, explicit: str = None):
        """
               Initialize the Copyleft class.
               :param debug: Enable debug mode
               :param trace: Enable trace mode (default True)
               :param quiet: Enable quiet mode
               :param filepath: Path to the file containing component data
               :param format: Output format ('json' or 'md')
               :param status: Path to save the status output
               :param output: Path to save detailed output
               :param include: Licenses to include in the analysis
               :param exclude: Licenses to exclude from the analysis
               :param explicit: Explicitly defined licenses
        """
        super().__init__(debug, trace, quiet, filepath, format, status, output, name='Copyleft Policy')
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
            'details':  json.dumps(details, indent=2),
            'summary': f"{len(components)} component(s) with copyleft licenses were found."
        }


    def _markdown(self, components: list) -> Dict[str,Any]:
        """
        Format the components with copyleft licenses as Markdown.

        :param components: List of components with copyleft licenses
        :return: Dictionary with formatted Markdown details and summary
        """
        headers = ['Component', 'Version', 'License', 'URL', 'Copyleft']
        centeredColumns = [1, 4]
        rows: [[]]= []
        for component in components:
            for license in component['licenses']:
                row = [
                    component['purl'],
                    component['version'],
                    license['spdxid'],
                    license['url'],
                    'YES' if license['copyleft'] else 'NO'
                ]
                rows.append(row)

        return  {
            'details': f"### Copyleft licenses \n {generate_table(headers,rows,centeredColumns)}",
            'summary' : f"{len(components)} component(s) with copyleft licenses were found."
        }

    def _get_formatter(self)-> Callable[[List[dict]], Dict[str,Any]] or None:
        """
            Get the appropriate formatter function based on the specified format.
            :return: Formatter function (either _json or _markdown)
        """
        valid_format = self._is_valid_format()
        if not valid_format:
            return None

        function_map = {
            'json': self._json,
            'md': self._markdown
        }
        return function_map[self.format]

    def _filter_components_with_copyleft_licenses(self, components: list) -> list:
        """
           Filter the components list to include only those with copyleft licenses.

           :param components: List of all components
           :return: List of components with copyleft licenses
        """
        filtered_components = []
        for component in components:
            copyleft_licenses = [license for license in component['licenses'] if license['copyleft']]
            if copyleft_licenses:
                filtered_component = component
                filtered_component['licenses'] = copyleft_licenses
                del filtered_component['status']
                filtered_components.append(filtered_component)

        self.print_debug(f"Copyleft components: {filtered_components}")
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
        if not self._init():
            return PolicyStatus.ERROR.value, {}

        self._debug()

        license_util.init(self.include, self.exclude, self.explicit)
        components = self._get_components()
        if components is None:
            return PolicyStatus.ERROR.value, {}

        copyleft_components = self._filter_components_with_copyleft_licenses(components)
        formatter = self._get_formatter()
        if formatter is None:
            return PolicyStatus.ERROR.value, {}

        results = formatter(copyleft_components)
        ## Save outputs  if required
        self.print_to_file_or_stdout(results['details'], self.output)
        self.print_to_file_or_stderr(results['summary'], self.status)

        if len(copyleft_components) <= 0:
            return PolicyStatus.FAIL.value, results
        return PolicyStatus.SUCCESS.value, results




