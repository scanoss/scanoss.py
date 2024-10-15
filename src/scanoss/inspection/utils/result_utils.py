from collections import defaultdict
from dataclasses import dataclass
from enum import Enum
from typing import Dict, Any, List, Optional

from scanoss.inspection.utils.license_utils import license_util


class ComponentID(Enum):
    FILE = "file"
    SNIPPET = "snippet"
    DEPENDENCY = "dependency"


def _append_component(components: Dict[str, Any], new_component: Dict[str, Any]) -> Dict[str, Any]:

    component_key = f"{new_component['purl'][0]}@{new_component['version']}"
    components[component_key] = {
        'purl': new_component['purl'][0],
        'version': new_component['version'],
        'licenses': {}
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
