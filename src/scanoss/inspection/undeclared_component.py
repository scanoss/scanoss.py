import json
from typing import Dict, Any, Callable, List
from scanoss.inspection.policy_check import PolicyCheck, PolicyStatus
from scanoss.inspection.utils.markdown_utils import generate_table


class UndeclaredComponent(PolicyCheck):
    """
      SCANOSS UndeclaredComponent class \n
      Inspects for undeclared components
      """

    def __init__(self, debug: bool = False, trace: bool = True, quiet: bool = False, filepath: str = None,
                 format: str = 'json', status: str = None, output: str = None):
        """
               Initialize the UndeclaredComponent class.

               :param debug: Enable debug mode
               :param trace: Enable trace mode (default True)
               :param quiet: Enable quiet mode
               :param filepath: Path to the file containing component data
               :param format: Output format ('json' or 'md')
               :param status: Path to save status output
               :param output: Path to save detailed output
        """
        super().__init__(debug, trace, quiet, filepath, format, status, output, name='Undeclared Components Policy')
        self.filepath = filepath
        self.format = format
        self.output = output
        self.status = status


    def _get_undeclared_component(self, components: list)-> list:
        """
           Filter the components list to include only undeclared components.

           :param components: List of all components
           :return: List of undeclared components
        """
        undeclared_components = []
        for component in components:
            if component['status'] == 'pending':
                del component['status']
                undeclared_components.append(component)
        # end for
        return undeclared_components

    def _json(self, components: list) -> Dict[str, Any]:
        """
        Format the undeclared components as JSON.

        :param components: List of undeclared components
        :return: Dictionary with formatted JSON details and summary
        """
        return {
            'details':  json.dumps({ 'components': components}, indent=2),
            'summary': f"{len(components)} undeclared component(s) were found.\n"
                       f" Add the following snippet into your `sbom.json` file \n"
                       f" ```json \n {json.dumps(self._generate_sbom_file(components), indent=2)}``` \n ",
        }


    def _markdown(self, components: list) -> Dict[str,Any]:
        """
         Format the undeclared components as Markdown.

         :param components: List of undeclared components
         :return: Dictionary with formatted Markdown details and summary
         """
        headers = ['Component', 'Version', 'License']
        rows: [[]]= []
        for component in components:
            licenses = " - ".join(license.get('spdxid', 'Unknown') for license in component['licenses'])

            rows.append([component['purl'], component['version'], licenses])
        #`#### Add the following snippet into your \`sbom.json\` file \n \`\`\`json \n ${snippet} \n \`\`\``
        return  {
            'details': f"### Undeclared components \n {generate_table(headers,rows)}",
            'summary': f"{len(components)} undeclared component(s) were found.\n"
                       f" Add the following snippet into your `sbom.json` file \n"
                       f" ```json \n {json.dumps(self._generate_sbom_file(components), indent=2)} ``` \n "
        }

    def _generate_sbom_file(self,components: list) -> list:
        """
         Generate a list of PURLs for the SBOM file.

         :param components: List of undeclared components
         :return: List of dictionaries containing PURLs
         """
        sbom = {}
        for component in components:
            sbom[component['purl']] = { 'purl': component['purl'] }

        return list(sbom.values())


    def _get_formatter(self) -> Callable[[List[dict]], Dict[str,Any]] or None:
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

        undeclared_components = self._get_undeclared_component(components)
        self.print_debug(f"Undeclared components: {undeclared_components}")
        formatter = self._get_formatter()
        if formatter is None:
            return PolicyStatus.ERROR.value, {}

        results = formatter(undeclared_components)
        self.print_to_file_or_stdout(results['details'], self.output)
        self.print_to_file_or_stderr(results['summary'], self.status)

        if len(undeclared_components) <= 0:
            return PolicyStatus.FAIL.value, results
        return PolicyStatus.SUCCESS.value, results
