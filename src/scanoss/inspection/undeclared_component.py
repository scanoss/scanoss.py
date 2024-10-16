import json
from types import MethodType
from typing import Dict, Any, Callable, List
from scanoss.inspection.policy_check import PolicyCheck
from scanoss.inspection.utils.markdown_utils import generate_table


class UndeclaredComponent(PolicyCheck):

    def __init__(self, debug: bool = False, trace: bool = True, quiet: bool = False, filepath: str = None,
                 format: str = None, status: str = None, output: str = None):
        super().__init__(debug, trace, quiet, filepath, format, status, output, name='Undeclared Components Policy')
        self.filepath = filepath
        self.format = format
        self.output = output
        self.status = status


    def _get_undeclared_component(self, components: list)-> list:
        undeclared_components = []
        for component in components:
            if component['status'] == 'pending':
                del component['status']
                undeclared_components.append(component)
        # end for
        return undeclared_components

    def _json(self, components: list) -> Dict[str, Any]:
        return {
            'details':  json.dumps({ 'components': components}, indent=2),
            'summary': f"{len(components)} undeclared component(s) were found.\n"
                       f" Add the following snippet into your \`sbom.json\` file \n"
                       f" \`\`\`json \n {json.dumps(self._generate_sbom_file(components), indent=2)} \n ",
        }


    def _markdown(self, components: list) -> Dict[str,Any]:
        headers = ['Component', 'Version', 'License']
        rows: [[]]= []
        for component in components:
            licenses = " - ".join(license.get('spdxid', 'Unknown') for license in component['licenses'])

            rows.append([component['purl'], component['version'], licenses])
        #`#### Add the following snippet into your \`sbom.json\` file \n \`\`\`json \n ${snippet} \n \`\`\``
        return  {
            'details': f"### Undeclared components \n {generate_table(headers,rows)}",
            'summary': f"{len(components)} undeclared component(s) were found.\n"
                       f" Add the following snippet into your \`sbom.json\` file \n"
                       f" \`\`\`json \n {json.dumps(self._generate_sbom_file(components), indent=2)} \n "
        }

    def _generate_sbom_file(self,components: list) -> list:
        sbom = []
        for component in components:
            purl = { 'purl': component['purl'] }
            sbom.append(purl)
        return sbom


    def _get_formatter(self) -> Callable[[List[dict]], str] :
        function_map = {
            'json': self._json,
            'md': self._markdown
        }
        return function_map[self.format]

    def run(self):
        self._debug()
        components = self._get_components()
        undeclared_components = self._get_undeclared_component(components)
        self.print_debug(f"Undeclared components: {undeclared_components}")
        formatter = self._get_formatter()
        results = formatter(undeclared_components)
        self.print_to_file_or_stdout(results['details'], self.output)
        self.print_to_file_or_stderr(results['summary'], self.status)
        return results
