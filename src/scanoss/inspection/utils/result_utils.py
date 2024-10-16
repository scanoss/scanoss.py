from enum import Enum
from typing import Dict, Any

from scanoss.inspection.utils.license_utils import license_util


class ComponentID(Enum):
    FILE = "file"
    SNIPPET = "snippet"
    DEPENDENCY = "dependency"


def _append_component(components: Dict[str, Any], new_component: Dict[str, Any]) -> Dict[str, Any]:
    """
    Append a new component to the components dictionary.

    This function creates a new entry in the components dictionary for the given component,
    or updates an existing entry if the component already exists. It also processes the
    licenses associated with the component.

    :param components: The existing dictionary of components
    :param new_component: The new component to be added or updated
    :return: The updated components dictionary
    """
    component_key = f"{new_component['purl'][0]}@{new_component['version']}"
    components[component_key] = {
        'purl': new_component['purl'][0],
        'version': new_component['version'],
        'licenses': {},
        'status': new_component['status'],
    }

    # Process licenses for this component
    for l in new_component['licenses']:
        spdxid = l['name']
        components[component_key]['licenses'][spdxid] = {
            'spdxid': spdxid,
            'copyleft': license_util.is_copyleft(spdxid),
            'url': l.get('url')
        }

    return components


def get_components(results: Dict[str, Any]) -> list:
    """
        Process the results dictionary to extract and format component information.

        This function iterates through the results dictionary, identifying components from
        different sources (files, snippets, and dependencies). It consolidates this information
        into a list of unique components, each with its associated licenses and other details.

        :param results: A dictionary containing the raw results of a component scan
        :return: A list of dictionaries, each representing a unique component with its details
    """
    components = {}
    for component in results.values():
        for c in component:
            if c['id'] in [ComponentID.FILE.value, ComponentID.SNIPPET.value]:
                component_key = f"{c['purl'][0]}@{c['version']}"

                # Initialize or update the component entry
                if component_key not in components:
                    components = _append_component(components, c)

            if c['id'] == ComponentID.DEPENDENCY.value:
                for d in c['dependencies']:
                    component_key = f"{d['purl'][0]}@{d['version']}"

                    if component_key not in components:
                        components = _append_component(components, d)
                # End of for loop
            # End if
        # End if
    results = list(components.values())
    for component in results:
        component['licenses'] = list(component['licenses'].values())

    return results
