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


Settings
========
The ``settings`` object allows you to configure various aspects of the scanning process. Currently, it provides control over which files should be skipped during scanning through the ``skip`` property.

Skip Configuration
------------------
The ``skip`` object lets you define rules for excluding files from being scanned. This can be useful for improving scan performance and avoiding unnecessary processing of certain files.

Properties
~~~~~~~~~~

skip.patterns
^^^^^^^^^^^^^
A list of patterns that determine which files should be skipped during scanning. The patterns follow the same format as ``.gitignore`` files. For more information, see the `gitignore patterns documentation <https://git-scm.com/docs/gitignore#_pattern_format>`_.

:Type: Array of strings
:Required: No
:Example:
    .. code-block:: json

        {
            "settings": {
            "skip": {
                "patterns": [
                    "*.log",
                    "!important.log",
                    "temp/",
                    "debug[0-9]*.txt",
                    "src/client/specific-file.js",
                    "src/nested/folder/"
                ]
            }
        }

Pattern Format Rules
''''''''''''''''''''
* Patterns are matched **relative to the scan root directory**
* A trailing slash indicates a directory (e.g., ``path/`` matches only directories)
* An asterisk ``*`` matches anything except a slash
* Two asterisks ``**`` match zero or more directories (e.g., ``path/**/folder`` matches ``path/to``, ``path/to/folder``, ``path/to/folder/b``)
* Range notations like ``[0-9]`` match any character in the range
* Question mark ``?`` matches any single character except a slash


Examples with Explanations
''''''''''''''''''''''''''
.. code-block:: none

    # Match all .txt files
    *.txt

    # Match all .log files except important.log
    *.log
    !important.log

    # Match all files in the build directory
    build/

    # Match all .pdf files in docs directory and its subdirectories
    docs/**/*.pdf

    # Match files like test1.js, test2.js, etc.
    test[0-9].js

skip.sizes
^^^^^^^^^^
Rules for skipping files based on their size.

:Type: Object
:Required: No
:Properties:
    * ``min`` (integer): Minimum file size in bytes
    * ``max`` (integer): Maximum file size in bytes (Required)
:Example:
    .. code-block:: json

        {
          "settings": {
            "skip": {
              "sizes": {
                "min": 100,
                "max": 1000000
              }
            }
          }
        }

Complete Example
-------------------
Here's a comprehensive example combining pattern and size-based skipping:

.. code-block:: json

    {
      "settings": {
        "skip": {
          "patterns": [
            "# Node.js dependencies",
            "node_modules/",
            
            "# Build outputs",
            "dist/",
            "build/",
            
            "# Logs except important ones",
            "*.log",
            "!important.log",
            
            "# Temporary files",
            "temp/",
            "*.tmp",
            
            "# Debug files with numbers",
            "debug[0-9]*.txt",
            
            "# All test files in any directory",
            "**/*test.js"
          ],
          "sizes": {
            "min": 512,
            "max": 5242880
          }
        }
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

Usage
-----

You can pass the settings file path as an argument to the CLI

.. code-block:: bash

    $ scanoss-py scan . --settings /path/to/settings.json

If no settings file is provided, the default settings file will be used.
The default location for the settings file is ``scanoss.json`` in the current working directory.
If this file does not exist, settings will be omitted.

You can also skip the default settings file:

.. code-block:: bash

    $ scanoss-py scan . --skip-settings-file