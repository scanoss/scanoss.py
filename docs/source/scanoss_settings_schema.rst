Settings File
======================

SCANOSS provides a settings file to customize the scanning process. The settings file is a JSON file that contains project information and BOM (Bill of Materials) rules. It allows you to include, remove, or replace components in the BOM before and after scanning.

The schema is available to download :download:`here </_static/scanoss-settings-schema.json>`

Schema Overview
---------------

The settings file consists of two main sections:

Project Information
-------------------

The ``self`` section contains basic information about your project:

.. code-block:: json

    {
        "self": {
            "name": "my-project",
            "license": "MIT",
            "description": "Project description"
        }
    }

BOM Rules
---------

The ``bom`` section defines rules for modifying the BOM before and after scanning. It contains three main operations:

1. Include Rules
~~~~~~~~~~~~~~~~

Rules for adding context when scanning. These rules will be sent to the SCANOSS API meaning they have more chance of being considered part of the resulting scan. 

.. code-block:: json

    {
        "bom": {
            "include": [
                {
                    "path": "/path/to/file",
                    "purl": "pkg:npm/vue@2.6.12",
                    "comment": "Optional comment"
                }
            ]
        }
    }

2. Remove Rules
~~~~~~~~~~~~~~~

Rules for removing files from results after scanning. These rules will be applied to the results file after scanning. The post processing happens on the client side.

.. code-block:: json

    {
        "bom": {
            "remove": [
                {
                    "path": "/path/to/file",
                    "purl": "pkg:npm/vue@2.6.12",
                    "comment": "Optional comment"
                }
            ]
        }
    }

3. Replace Rules
~~~~~~~~~~~~~~~~

Rules for replacing components after scanning. These rules will be applied to the results file after scanning. The post processing happens on the client side.

.. code-block:: json

    {
        "bom": {
            "replace": [
                {
                    "path": "/path/to/file",
                    "purl": "pkg:npm/vue@2.6.12",
                    "replace_with": "pkg:npm/vue@2.6.14",
                    "license": "MIT",
                    "comment": "Optional comment"
                }
            ]
        }
    }

Important Notes
---------------

Matching Rules
~~~~~~~~~~~~~~

1. **Full Match**: Requires both PATH and PURL to match. It means the rule will be applied ONLY to the specific file with the matching PURL and PATH.
2. **Partial Match**: Matches based on either:
   - File path only (PURL is optional). It means the rule will be applied to all files with the matching path.
   - PURL only (PATH is optional). It means the rule will be applied to all files with the matching PURL.
   
File Paths
~~~~~~~~~~

- All paths should be specified relative to the scanned directory
- Use forward slashes (``/``) as path separators

Given the following example directory structure:

.. code-block:: text

    project/
    ├── src/
    │   └── component.js
    └── lib/
        └── utils.py

- If the scanned directory is ``/project/src``, then:
    - ``component.js`` is a valid path
    - ``lib/utils.py`` is an invalid path and will not match any files
- If the scanned directory is ``/project``, then:
    - ``src/component.js`` is a valid path
    - ``lib/utils.py`` is a valid path

Package URLs (PURLs)
~~~~~~~~~~~~~~~~~~~~

PURLs must follow the Package URL specification:

- Format: ``pkg:<type>/<namespace>/<name>@<version>``
- Examples:
  - ``pkg:npm/vue@2.6.12``
  - ``pkg:golang/github.com/golang/go@1.17.3``
- Must be valid and include all required components
- Version is strongly recommended but optional

Example Configuration
---------------------

Here's a complete example showing all sections:

.. code-block:: json

    {
        "self": {
            "name": "example-project",
            "license": "Apache-2.0",
            "description": "Example project configuration"
        },
        "bom": {
            "include": [
                {
                    "path": "src/lib/component.js",
                    "purl": "pkg:npm/lodash@4.17.21",
                    "comment": "Include lodash dependency"
                }
            ],
            "remove": [
                {
                    "purl": "pkg:npm/deprecated-pkg@1.0.0",
                    "comment": "Remove deprecated package"
                }
            ],
            "replace": [
                {
                    "path": "src/utils/helper.js",
                    "purl": "pkg:npm/old-lib@1.0.0",
                    "replace_with": "pkg:npm/new-lib@2.0.0",
                    "license": "MIT",
                    "comment": "Upgrade to newer version"
                }
            ]
        }
    }