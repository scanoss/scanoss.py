import json
from typing import Dict, Any
from scanoss.inspection.policy_check import PolicyCheck
from scanoss.inspection.utils.license_utils import license_util
from scanoss.inspection.utils.markdown_utils import generate_table


class Copyleft(PolicyCheck):

    def __init__(self, debug: bool = False, trace: bool = True, quiet: bool = False, filepath: str = None,
                 format: str = None, status: str = None, output: str = None, include: str = None, exclude: str = None, explicit: str = None):
        super().__init__(debug, trace, quiet, filepath, format, status, output)
        self.filepath = filepath
        self.format = format
        self.output = output
        self.status = status
        license_util.init(include, exclude, explicit)

    def _json(self, comp: list) -> Dict[str, Any]:
        return {
            'details':  json.dumps({ 'components': comp}, indent=2),
            'summary': ""
        }


    def _markdown(self, components: list) -> Dict[str,Any]:
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
            'summary' : f"#### {len(components)} component(s) with copyleft licenses were found."
        }

    def _get_formatter(self):
        function_map = {
            'json': self._json,
            'md': self._markdown
        }
        return function_map[self.format]

    def _filter_components_with_copyleft_licenses(self, components: list) -> list:
        filtered_components = []

        for component in components:
            copyleft_licenses = [license for license in component['licenses'] if license['copyleft']]

            if copyleft_licenses:
                filtered_component = component
                filtered_component['licenses'] = copyleft_licenses
                del filtered_component['status']
                filtered_components.append(filtered_component)

        return filtered_components

    def run(self) -> str:
        components = self._get_components()
        copyleft_components = self._filter_components_with_copyleft_licenses(components)
        formatter = self._get_formatter()
        results = formatter(copyleft_components)
        ## Save outputs  if required
        self.print_to_file_or_stdout(results['details'], self.output)
        self.print_to_file_or_stderr(results['summary'], self.status)
        return results




