=======================================
Documentation for scanoss-py
=======================================

Introduction
============
In order to complete a Software Composition Analysis of your project, you will 
need to scan the fingerprints of the source code against a knowledge base (for example, the `Open Source Software Knowledge Base <https://www.softwaretransparency.org/osskb>`_).

Notice we mention fingerprints, and not the source code itself. Keeping the privacy of your information is the most important rule we follow,
and what makes us different than our competitors. In order to achieve this, the SCANOSS Platform calculates file and snippet fingerprints 
(32-bit identifiers calculated with the `winnowing algorithm <https://github.com/scanoss/wfp>`_).

The fingerprints of each file or snippet are then sent to the `SCANOSS API <https://github.com/scanoss/API>`_, that means you are scanning against the knowledge base and not the other
way around.

One way to query the SCANOSS Platform is through our Python package: `scanoss-py <https://github.com/scanoss/scanoss.py>`_.

.. note::
   All of SCANOSS software is open source and free to use, explore our `GitHub Organization page <https://github.com/scanoss>`_. You can contribute to this tool, for more information check the `contribution guidelines <https://github.com/scanoss/scanoss.py/blob/main/CONTRIBUTING.md>`_ for this project.

Features
========
* The package can be run from the command line, or consumed from another Python script
* Scan your source code fingerprints against a knowledge base
* Dependency detection
* Decoration services for cryptographic algorithm, vulnerabilities, semgrep issues/findings and component version detection
* Generate an SBOM (software bill of materials) in SPDX-Lite and CycloneDX

Installation
============
To install (from `pypi.org <https://pypi.org/project/scanoss/>`_), run: ``pip3 install scanoss``.

------------
Requirements
------------

Python 3.9 or higher.

The dependencies can be found in the `requirements.txt <https://github.com/scanoss/scanoss.py/blob/main/requirements.txt>`_ and `requirements-dev.txt <https://github.com/scanoss/scanoss.py/blob/main/requirements-dev.txt>`_ files.

To install dependencies run: ``pip3 install -r requirements.txt`` and ``pip3 install requirements-dev.txt``.

To enable dependency scanning, an extra tool is required: scancode-toolkit.

To install it run: ``pip3 install -r requirements-scancode.txt``


.. include:: scanoss_settings_schema.rst


Commands and arguments
======================


------------------
Scanning: scan, sc
------------------

Scans a directory or file (source code or ``.wfp`` fingerprint file) and shows results on the STDOUT, by default. This command is highly customizable, from the output format to the matching selection logic using an SBOM file, everything can be set to your preference.

.. code-block:: bash

   scanoss-py scan <file or directory>


.. list-table:: 
   :widths: 20 30
   :header-rows: 1

   * - Argument
     - Description
   * - --wfp <wfp file>, -w <wfp file>
     - Allows to scan a wfp (winnowing fingerprint) file instead of a directory
   * - --dep <dependency file>, -p <dependency file>
     - Use a dependency file instead of a directory
   * - --identify <SBOM file>, -i <SBOM file>
     - Scan and identify components in SBOM file (an API key is required for this feature)
   * - --ignore <SBOM file>, -n <SBOM file>
     - Ignore components specified in the IGNORE SBOM file (an API key is required for this feature)
   * - --format <format>, -f <format>
     - Indicates the result output format: {plain, cyclonedx, spdxlite, csv} (optional - default plain)
   * - --flags <FLAGS>, -F <FLAGS>
     - Sends scanning flags (or definitions)
   * - --threads <THREADS>, -T <THREADS>
     - Number of threads to use while scanning (optional - default 10 - max 30)
   * - --skip-snippets, -S
     - Skip the generation of snippets
   * - --post-size <POST_SIZE>, -P <POST_SIZE>
     - Number of kilobytes to limit the post to while scanning (optional - default 64)
   * - --timeout <TIMEOUT>, -M <TIMEOUT>
     - Timeout (in seconds) for API communication (optional - default 120)
   * - --no-wfp-output
     - Skip WFP file generation
   * - --all folders
     - Scan all folders
   * - --all-extensions
     - Scan all file extensions
   * - --all-hidden
     - Scan all hidden file/folders
   * - --obfuscate
     - Obfuscate fingerprints
   * - --dependencies, -D
     - Add dependency scanning 
   * - --dependencies-only
     - Run dependency scanning only
   * - --sc-command <SC_COMMAND>
     - Scancode command and path if required (optional - default scancode)
   * - --sc-timeout <SC_TIMEOUT>
     - Timeout (in seconds) for Scancode to complete (optional - default 600)
   * - --apiurl <API_URL>
     - SCANOSS API URL (optional - default https://api.osskb.org/api/scan/direct)
   * - --ignore-cert-errors
     - Ignore certificate errors
   * - --key <KEY>, -k <KEY>
     - SCANOSS API Key token (optional - not required for default API_URL)
   * - --proxy <PROXY>
     - Proxy URL to use for connections, can also use the environment variable ``HTTPS_PROXY`` (optional)
   * - --pac <PAC>
     - Proxy auto configuration (optional).
   * - --ca-cert <CA_CERT>
     - Alternative certificate PEM file, can also use the environment variables ``REQUEST_CA_BUNDLE`` and ``GRPC_DEFAULT_SSL_ROOTS_FILE_PATH`` (optional)
   * - --api2url <API2URL>
     - SCANOSS gRPC API 2.0 URL (optional - default https://api.osskb.org/api/scan/direct)
   * - --grpc-proxy <GRPC_PROXY>
     - GRPC Proxy URL to use for connections, can also us the environment variable ``GRPC_PROXY`` (optional)
   
-------------------------------------------
Generate fingerprints: fingerprint, fp, wfp
-------------------------------------------

Calculates hashes for a directory or file and shows them on the STDOUT.

.. code-block:: bash

   scanoss-py fingerprint <file or directory>


.. list-table:: 
   :widths: 20 30
   :header-rows: 1

   * - Argument
     - Description
   * - --output <file name>, -o <file name>
     - Output result file name (optional - default STDOUT)
   * - --obfuscate
     - Obfuscate fingerprints
   * - --skip-snippets, -S
     - Skip the generation of snippets
   * - --all-extensions
     - Fingerprint all file extensions
   * - --all-folders
     - Fingerprint all folders
   * - --all-hidden 
     - Fingerprint all hidden files/folders

-----------------------------------------
Detect dependencies: dependencies, dp, dep
-----------------------------------------

Scan source code for dependencies, but do not decorate them.

.. code-block:: bash

   scanoss-py dependencies <>


.. list-table:: 
   :widths: 20 30
   :header-rows: 1

   * - Argument
     - Description
   * - --output <file name>, -o <file name>
     - Output result file name (optional - default STDOUT)
   * - --container <image_name:tag>
     - Analyze dependencies from a Docker container image instead of a directory
   * - --sc-command SC_COMMAND
     - Scancode command and path if required (optional - default scancode)
   * - --sc-timeout SC_TIMEOUT
     - Timeout (in seconds) for scancode to complete (optional - default 600)

.. note::
   Remember that in order to enable dependency scanning, an extra tool is required: **scancode-toolkit**. To install it, run: ``pip3 install -r requirements-scancode.txt``.

--------------------------
File count: file_count, fc
--------------------------

Search the source tree and produce a file type summary.

.. code-block:: bash

   scanoss-py file_count <directory>


.. list-table:: 
   :widths: 20 30
   :header-rows: 1

   * - Argument
     - Description
   * - --output <file name>, -o <file name>
     - Output result file name (optional - default STDOUT)
   * - --all-hidden
     - Scan all hidden files/directories

-----------------------------------------
Format conversion: convert, cv, cnv, cvrt
-----------------------------------------

Convert file format to plain, SPDX-Lite, CycloneDX or csv.

.. code-block:: bash

   scanoss-py convert -i <input file> --format <example, spdxlite> -o <output file>


.. list-table:: 
   :widths: 20 30
   :header-rows: 1

   * - Argument
     - Description
   * - -input <file>, -i <file>
     - Input file name.
   * - --output <file name>, -o <file name>
     - Output result file name (optional - default STDOUT)
   * - --format <format>, -f <format>
     - Indicates the result output format: {plain, cyclonedx, spdxlite, csv}. (optional - default plain)

--------------------------------
Folder Scanning: folder-scan, fs
--------------------------------

Performs a comprehensive scan of a directory using folder hashing to identify components and their matches.

.. code-block:: bash

   scanoss-py folder-scan <directory>

.. list-table:: 
   :widths: 20 30
   :header-rows: 1

   * - Argument
     - Description
   * - --output <file name>, -o <file name>
     - Output result file name (optional - default STDOUT)
   * - --format <format>, -f <format>
     - Output format: {json, cyclonedx} (optional - default json)
   * - --timeout <seconds>, -M <seconds>
     - Timeout in seconds for API communication (optional - default 600)
   * - --rank-threshold <number>
     - Filter results to only show those with rank value at or below this threshold (e.g., --rank-threshold 3 returns results with rank 1, 2, or 3). Lower rank values indicate higher quality matches.
   * - --settings <file>, -st <file>
     - Settings file to use for scanning (optional - default scanoss.json)
   * - --skip-settings-file, -stf
     - Skip default settings file (scanoss.json) if it exists
   * - --key <token>, -k <token>
     - SCANOSS API Key token (optional - not required for default OSSKB URL)
   * - --proxy <url>
     - Proxy URL to use for connections
   * - --pac <file/url>
     - Proxy auto configuration. Specify a file, http url or "auto"
   * - --ca-cert <file>
     - Alternative certificate PEM file
   * - --api2url <url>
     - SCANOSS gRPC API 2.0 URL (optional - default: https://api.osskb.org)
   * - --grpc-proxy <url>
     - GRPC Proxy URL to use for connections

--------------------------------
Folder Hashing: folder-hash, fh
--------------------------------

Generates cryptographic hashes for files in a given directory and its subdirectories.

.. code-block:: bash

   scanoss-py folder-hash <directory>

.. list-table:: 
   :widths: 20 30
   :header-rows: 1

   * - Argument
     - Description
   * - --output <file name>, -o <file name>
     - Output result file name (optional - default STDOUT)
   * - --format <format>, -f <format>
     - Output format: {json} (optional - default json)
   * - --settings <file>, -st <file>
     - Settings file to use for scanning (optional - default scanoss.json)
   * - --skip-settings-file, -stf
     - Skip default settings file (scanoss.json) if it exists

Both commands also support these general options:
   * --debug, -d: Enable debug messages
   * --trace, -t: Enable trace messages
   * --quiet, -q: Enable quiet mode

------------------------------------
Container Scanning: container-scan, cs
------------------------------------

Scans Docker container images for dependencies, extracting and analyzing components within containerized applications.

.. code-block:: bash

   scanoss-py container-scan -i <image_name:tag>

.. list-table:: 
   :widths: 20 30
   :header-rows: 1

   * - Argument
     - Description
   * - --image <image_name:tag>, -i <image_name:tag>
     - Docker image name and tag to scan (required)
   * - --output <file name>, -o <file name>
     - Output result file name (optional - default STDOUT)
   * - --include-base-image
     - Include base image dependencies in the scan results
   * - --format <format>, -f <format>
     - Output format: {json} (optional - default json)
   * - --timeout <seconds>, -M <seconds>
     - Timeout in seconds for API communication (optional - default 600)
   * - --key <token>, -k <token>
     - SCANOSS API Key token (optional - not required for default OSSKB URL)
   * - --proxy <url>
     - Proxy URL to use for connections
   * - --ca-cert <file>
     - Alternative certificate PEM file

-----------------
Crypto: crypto, cr
-----------------

Provides subcommands to retrieve cryptographic information for components.

.. code-block:: bash

   scanoss-py crypto <subcommand>

Subcommands:
~~~~~~~~~~~~

**algorithms (alg)**
  Retrieve cryptographic algorithms for the given components.

  .. code-block:: bash

     scanoss-py crypto algorithms --purl <purl_string>

  .. list-table::
     :widths: 20 30
     :header-rows: 1

     * - Argument
       - Description
     * - --with-range
       - Returns the list of versions in the specified range that contains cryptographic algorithms. (Replaces the previous --range option)

**hints**
  Retrieve encryption hints for the given components.

  .. code-block:: bash

     scanoss-py crypto hints --purl <purl_string>

  .. list-table::
     :widths: 20 30
     :header-rows: 1

     * - Argument
       - Description
     * - --with-range
       - Returns the list of versions in the specified range that contains encryption hints.

**versions-in-range (vr)**
  Given a list of PURLs and version ranges, get a list of versions that do/don't contain crypto algorithms.

  .. code-block:: bash

     scanoss-py crypto versions-in-range --purl <purl_string_with_range>

Common Crypto Arguments:
~~~~~~~~~~~~~~~~~~~~~~~~
The following arguments are common to the ``algorithms``, ``hints``, and ``versions-in-range`` subcommands:

.. list-table::
   :widths: 20 30
   :header-rows: 1

   * - Argument
     - Description
   * - --purl <PURL>, -p <PURL>
     - Package URL (PURL) to process. Can be specified multiple times.
   * - --input <file>, -i <file>
     - Input file name containing PURLs.
   * - --output <file name>, -o <file name>
     - Output result file name (optional - default STDOUT).
   * - --timeout <seconds>, -M <seconds>
     - Timeout (in seconds) for API communication (optional - default 600).
   * - --key <KEY>, -k <KEY>
     - SCANOSS API Key token (optional - not required for default OSSKB URL).
   * - --api2url <API2URL>
     - SCANOSS gRPC API 2.0 URL (optional - default: https://api.osskb.org).
   * - --grpc-proxy <GRPC_PROXY>
     - GRPC Proxy URL to use for connections.
   * - --ca-cert <CA_CERT>
     - Alternative certificate PEM file.
   * - --debug, -d
     - Enable debug messages.
   * - --trace, -t
     - Enable trace messages, including API posts.
   * - --quiet, -q
     - Enable quiet mode.

-----------------
Component:
-----------------

To be done

------------------------
Utilities: utilities, ut
------------------------

.. code-block:: bash

   scanoss-py utilities


.. list-table:: 
   :widths: 20 30
   :header-rows: 1

   * - Argument
     - Description
   * - fast
     - SCANOSS fast winnowing (requires the `SCANOSS Winnowing Python Package <https://pypi.org/project/scanoss-winnowing/>`_)
   * - certloc, cl
     - Display the location of Python CA certificates
   * - cert-download, cdl, cert-dl 
     - Download the specified server's SSL PEM certificate
   * - pac-proxy, pac
     - Use Proxy Auto-Config to determine proxy configuration

-----------------
General Arguments
-----------------

.. list-table:: 
   :widths: 20 30
   :header-rows: 1

   * - Argument
     - Description
   * - -debug, -d
     - Enable debug messages
   * - --trace, -t
     - Enable trace messages, including API posts
   * - --quiet, -q
     - Enable quiet mode


Package consumption 
====================

This package can be run from the command line, or consumed from another Python script. A good example of how to consume it can be found in this `file <https://github.com/scanoss/scanoss.py/blob/main/src/scanoss/cli.py>`_.


In general the easiest way is to import the required module as follows:

.. code-block:: python

   from scanoss.scanner import Scanner

   def main():
      scanner = Scanner()
      scanner.scan_folder( '.' )
    
   if __name__ == "__main__":
      main()
   

Alternatively, there is a docker image of the compiled package, which can be found in this `repository <https://github.com/scanoss/scanoss.py/pkgs/container/scanoss-py>`_. Details on how to run it can be found in this `file <https://github.com/scanoss/scanoss.py/blob/main/GHCR.md>`_.


Integrations
============

At SCANOSS we want to provide **easy recipes for practical solutions**, that is the reason we are constantly working on building integrations for our software. No need to adapt your existing systems to work with our software, we will adapt our software to your needs.


From CI/CD integrations with `Jenkins <https://github.com/scanoss/integration-jenkins>`_ and `GitHub Actions <https://github.com/scanoss/gha-code-scan>`_, to our `SonarQube plugin <https://github.com/scanoss/scanoss-sonar-plugin>`_ and our most recent `VSCode extension <https://github.com/scanoss/vscode.extension>`_. We are always working on making our software as easy to access, consume and integrate as possible. 


The full list of existing integrations is down below:

.. list-table:: 
   :widths: 20 30
   :header-rows: 1

   * - Integration
     - Description
   * - `Jenkins <https://github.com/scanoss/integration-jenkins>`_
     - Integrate scanoss-py into your pipelines
   * - `GitHub Actions <https://github.com/scanoss/gha-code-scan>`_
     - Enhance your software development process with the SCANOSS Code Scan Action
   * - `SonarQube <https://github.com/scanoss/scanoss-sonar-plugin>`_
     - Scan your code with the SCANOSS plugin for SonarQube
   * - `Visual Studio Code <https://github.com/scanoss/vscode.extension>`_
     - Software Composition Analysis as you code 

Best practices
==============

|

----------------------------------------------------------------------
*Choose the tool based on your use case, and not the other way around*
----------------------------------------------------------------------

SCANOSS offers many tools and software in the field of Software Composition Analysis, and many have similar features.


For example, you can perform scans and generate software bill of materials (SBOM) with scanoss-py and the `SBOM Workbench <https://github.com/scanoss/sbom-workbench>`_, but that doesn't mean these tools are interchangeable. The SBOM Workbench's GUI can be an advantage for auditors and such, but may be a complication for developers that need to integrate an SCA solution into an existing workflow.


There is also the case for language preferences, we also offer a `Javascript package <https://github.com/scanoss/scanoss.js>`_ and a `Java SDK <https://github.com/scanoss/scanoss.java>`_ so you have freedom to consume the SCANOSS API however you want.

|

-------------------------------
*Get the most accurate results*
-------------------------------


License
=======
The Scanoss Open Source scanoss-py package is released under the MIT license.


.. toctree::
   :maxdepth: 2
   :hidden:
   :caption: Links

   SCANOSS Website <https://www.scanoss.com/>
   GitHub <https://github.com/scanoss>
   Software transparency foundation <https://www.softwaretransparency.org/>
