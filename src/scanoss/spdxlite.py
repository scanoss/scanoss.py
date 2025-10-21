"""
SPDX-License-Identifier: MIT

  Copyright (c) 2021, SCANOSS

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

import datetime
import getpass
import hashlib
import json
import os.path
import re
import sys

import importlib_resources
from packageurl import PackageURL

from . import __version__


class SpdxLite:
    """
    SPDX Lite management class
    Handle all interaction with SPDX Lite formatting
    """

    def __init__(self, debug: bool = False, output_file: str = None):
        """
        Initialise the SpdxLite class
        """
        self.output_file = output_file
        self.debug = debug
        self._spdx_licenses = {}  # Used to lookup for valid SPDX license identifiers
        self._spdx_lic_names = {}  # Used to look for SPDX license identifiers by name

    @staticmethod
    def print_stderr(*args, **kwargs):
        """
        Print the given message to STDERR
        """
        print(*args, file=sys.stderr, **kwargs)

    def print_debug(self, *args, **kwargs):
        """
        Print debug message if enabled
        """
        if self.debug:
            self.print_stderr(*args, **kwargs)

    def parse(self, data: json):
        """
        Parse the given input (raw/plain) JSON string and return a summary
        :param data: json - JSON object
        :return: summary dictionary
        """
        if data is None:
            self.print_stderr('ERROR: No JSON data provided to parse.')
            return None
        if len(data) == 0:
            self.print_debug('Warning: Empty scan results provided. Returning empty summary.')
            return {}

        self.print_debug('Processing raw results into summary format...')
        return self._process_files(data)

    def _process_files(self, data: json) -> dict:
        """
            Process raw results and build a component summary.

            Args:
                data: JSON data containing raw results

            Returns:
                dict: The built summary dictionary
        """
        summary = {}
        for file_path in data:
            file_details = data.get(file_path)
            # summary is passed by reference and modified inside the function
            self._process_entries(file_path, file_details, summary)
        return summary

    def _process_entries(self, file_path: str, file_details: list, summary: dict):
        """
        Process entries for a single file.

        Args:
            file_path: Path to the file being processed
            file_details: Results of the file
            summary: Reference to summary dictionary that will be modified in place
        """
        for entry in file_details:
            id_details = entry.get('id')
            if not id_details or id_details == 'none':
                continue

            if id_details == 'dependency':
                self._process_dependency_entry(file_path, entry, summary)
            else:
                self._process_file_entry(file_path, entry, summary)

    def _process_dependency_entry(self, file_path: str, entry: dict, summary: dict):
        """
        Process a dependency type entry.

        Args:
            file_path: Path to the file being processed
            entry: The dependency entry to process
            summary: Reference to summary dictionary that will be modified in place
        """
        dependencies = entry.get('dependencies')
        if not dependencies:
            self.print_stderr(f'Warning: No Dependencies found for {file_path}')
            return

        for dep in dependencies:
            purl = dep.get('purl')
            if not self._is_valid_purl(file_path, dep, purl, summary):
                continue
            # Modifying the summary dictionary directly as it's passed by reference
            summary[purl] = self._create_dependency_summary(dep)

    def _process_file_entry(self, file_path: str, entry: dict, summary: dict):
        """
        Process file entry.

        Args:
            file_path: Path to the file being processed
            entry: Process file match entry
            summary: Reference to summary dictionary that will be modified in place
        """
        purls = entry.get('purl')
        if not purls:
            self.print_stderr(f'Purl block missing for {file_path}')
            return

        purl = purls[0] if purls else None
        if not self._is_valid_purl(file_path, entry, purl, summary):
            return

        summary[purl] = self._create_file_summary(entry)

    def _is_valid_purl(self, file_path: str, entry: dict, purl: str, summary: dict) -> bool:
        """
        Check if purl is valid and not already processed.

        Args:
            file_path: Path to the file being processed
            entry: The entry containing the PURL
            purl: The PURL to validate
            summary: Reference to summary dictionary to check for existing entries

        Returns:
            bool: True if purl is valid and not already processed
        """
        if not purl:
            self.print_stderr(f'Warning: No PURL found for {file_path}: {entry}')
            return False

        if summary.get(purl):
            self.print_debug(f'Component {purl} already stored: {summary.get(purl)}')
            return False

        return True

    def _create_dependency_summary(self, dep: dict) -> dict:
        """
        Create summary for dependency entry.

        This method extracts relevant fields from a dependency entry and creates a
        standardized summary dictionary. It handles fields like component, version,
        and URL, with special processing for licenses.

        Args:
            dep (dict): The dependency entry containing component information

        Returns:
            dict: A new summary dictionary containing the extracted and processed fields
        """
        summary = {}
        for field in ['component', 'version', 'url']:
            summary[field] = dep.get(field, '')
        summary['licenses'] = self._process_licenses(dep.get('licenses'))
        return summary

    def _create_file_summary(self, entry: dict) -> dict:
        """
        Create summary for file entry.

        This method extracts set of fields from file entry and creates a standardized summary dictionary.

        Args:
            entry (dict): The file entry containing the metadata to summarize

        Returns:
            dict: A new summary dictionary containing all extracted and processed fields
        """
        summary = {}
        fields = ['id', 'vendor', 'component', 'version', 'latest',
                  'url', 'url_hash', 'download_url']
        for field in fields:
            summary[field] = entry.get(field)
        summary['licenses'] = self._process_licenses(entry.get('licenses'))
        return summary

    def _process_licenses(self, licenses: list) -> list:
        """
            Process license information and remove duplicates.

            This method filters license information to include only licenses from trusted sources
            ('component_declared', 'license_file', 'file_header'). Licenses with an unspecified
            source (None or '') are allowed. Non-empty, non-allowed sources are excluded. It also
            removes any duplicate license names.
            The result is a simplified list of license dictionaries containing only the 'id' field.

            Args:
                licenses (list): A list of license dictionaries, each containing at least 'name'
                                 and 'source' fields. Can be None or empty.

            Returns:
                list: A filtered and deduplicated list of license dictionaries, where each
                      dictionary contains only an 'id' field matching the original license name.
                      Returns an empty list if input is None or empty.
            """
        if not licenses:
            return []

        processed_licenses = []
        seen_names = set()

        for license_info in licenses:
            name = license_info.get('name')
            source = license_info.get('source')
            if source not in (None, '') and source not in ("component_declared", "license_file", "file_header"):
                continue
            if name and name not in seen_names:
                processed_licenses.append({'id': name})
                seen_names.add(name)

        return processed_licenses

    def produce_from_file(self, json_file: str, output_file: str = None) -> bool:
        """
        Parse plain/raw input JSON file and produce SPDX Lite output
        :param json_file:
        :param output_file:
        :return: True if successful, False otherwise
        """
        if not json_file:
            self.print_stderr('ERROR: No JSON file provided to parse.')
            return False
        if not os.path.isfile(json_file):
            self.print_stderr(f'ERROR: JSON file does not exist or is not a file: {json_file}')
            return False
        with open(json_file, 'r') as f:
            success = self.produce_from_str(f.read(), output_file)
        return success

    def produce_from_json(self, data: json, output_file: str = None) -> bool:
        """
        Produce the SPDX Lite output from the input data
        :param data: JSON object
        :param output_file: Output file (optional)
        :return: True if successful, False otherwise
        """
        raw_data = self.parse(data)
        if raw_data is None:
            self.print_stderr('ERROR: No SPDX data returned for the JSON string provided.')
            return False
        if len(raw_data) == 0:
            self.print_debug('Warning: Empty scan results - generating minimal SPDX Lite document with no packages.')

        self.load_license_data()
        spdx_document = self._create_base_document(raw_data)
        self._process_packages(raw_data, spdx_document)
        return self._write_output(spdx_document, output_file)

    def _create_base_document(self, raw_data: dict) -> dict:
        """
            Create the base SPDX document structure.

            This method initializes a new SPDX document with standard fields required by
            the SPDX 2.2 specification. It generates a unique document namespace using
            a hash of the raw data and current timestamp.

            Args:
                raw_data (dict): The raw component data used to create a unique identifier
                                for the document namespace

            Returns:
                dict: A dictionary containing the base SPDX document structure with the
                      following fields:
                      - spdxVersion: The SPDX specification version
                      - dataLicense: The license for the SPDX document itself
                      - SPDXID: The document's unique identifier
                      - name: The name of the SBOM
                      - creationInfo: Information about when and how the document was created
                      - documentNamespace: A unique URI for this document
                      - documentDescribes: List of packages described (initially empty)
                      - hasExtractedLicensingInfos: List of licenses (initially empty)
                      - packages: List of package information (initially empty)
        """
        now = datetime.datetime.utcnow()
        md5hex = hashlib.md5(f'{raw_data}-{now}'.encode('utf-8')).hexdigest()

        return {
            'spdxVersion': 'SPDX-2.2',
            'dataLicense': 'CC0-1.0',
            'SPDXID': 'SPDXRef-DOCUMENT',
            'name': 'SCANOSS-SBOM',
            'creationInfo': self._create_creation_info(now),
            'documentNamespace': f'https://spdx.org/spdxdocs/scanoss-py-{__version__}-{md5hex}',
            'documentDescribes': [],
            'hasExtractedLicensingInfos': [],
            'packages': [],
        }

    def _create_creation_info(self, timestamp: datetime.datetime) -> dict:
        """
            Create the creation info section of an SPDX document.

            This method generates the creation information required by the SPDX specification,
            including timestamps, creator information, and document type.

            Args:
                timestamp (datetime.datetime): The UTC timestamp representing when the
                                              document was created

            Returns:
                dict: A dictionary containing creation information with the following fields:
                      - created: ISO 8601 formatted timestamp
                      - creators: List of entities involved in creating the document
                        (tool, person, and organization)
                      - comment: Additional information about the SBOM type
        """
        return {
            'created': timestamp.strftime('%Y-%m-%dT%H:%M:%SZ'),
            'creators': [
                f'Tool: SCANOSS-PY: {__version__}',
                f'Person: {getpass.getuser()}',
                'Organization: SCANOSS'
            ],
            'comment': 'SBOM Build information - SBOM Type: Build',
        }

    def _process_packages(self, raw_data: dict, spdx_document: dict):
        """
            Process packages and add them to the SPDX document.

            This method iterates through the raw component data, creates package information
            for each component, and adds them to the SPDX document. It also collects
            license references to be processed separately.

            Args:
                raw_data (dict): Dictionary of package data indexed by PURL
                                (Package URL identifiers)
                spdx_document (dict): Reference to the SPDX document being built,
                                     which will be modified in place

            Note:
                This method modifies the spdx_document dictionary in place by:
                1. Adding package information to the 'packages' list
                2. Adding package SPDXIDs to the 'documentDescribes' list
                3. Indirectly populating 'hasExtractedLicensingInfos' via _process_license_refs()
        """
        lic_refs = set()

        for purl, comp in raw_data.items():
            package_info = self._create_package_info(purl, comp, lic_refs)
            spdx_document['packages'].append(package_info)
            spdx_document['documentDescribes'].append(package_info['SPDXID'])

        self._process_license_refs(lic_refs, spdx_document)

    def _create_package_info(self, purl: str, comp: dict, lic_refs: set) -> dict:
        """
            Create package information for SPDX document.

            This method generates a complete package information entry following the SPDX
            specification format. It creates a unique identifier for the package based on
            its PURL and version, processes license information, and formats all required
            fields for the SPDX document.

            Args:
                purl (str): Package URL identifier for the component
                comp (dict): Component information dictionary containing metadata like
                            component name, version, URLs, and license information
                lic_refs (set): Reference to a set that will be populated with license
                               references found in this package. This set is modified in place.

            Returns:
                dict: A dictionary containing all required SPDX package fields including:
                      - name: Component name
                      - SPDXID: Unique identifier for this package within the document
                      - versionInfo: Component version
                      - downloadLocation: URL where the package can be downloaded
                      - homepage: Component homepage URL
                      - licenseDeclared: Formatted license expression
                      - licenseConcluded: NOASSERTION as automated conclusion isn't possible
                      - filesAnalyzed: False as files are not individually analyzed
                      - copyrightText: NOASSERTION as copyright text isn't available
                      - supplier: Organization name from vendor information
                      - externalRefs: Package URL reference for package manager integration
                      - checksums: MD5 hash of the package if available
        """
        lic_text = self._process_package_licenses(comp.get('licenses', []), lic_refs)
        comp_ver = comp.get('version')
        purl_ver = f'{purl}@{comp_ver}'
        purl_hash = hashlib.md5(purl_ver.encode('utf-8')).hexdigest()

        return {
            'name': comp.get('component'),
            'SPDXID': f'SPDXRef-{purl_hash}',
            'versionInfo': comp_ver,
            'downloadLocation': comp.get('download_url') or comp.get('url'),
            'homepage': comp.get('url', ''),
            'licenseDeclared': lic_text,
            'licenseConcluded': 'NOASSERTION',
            'filesAnalyzed': False,
            'copyrightText': 'NOASSERTION',
            'supplier': f'Organization: {comp.get("vendor", "NOASSERTION")}',
            'externalRefs': [
                {
                    'referenceCategory': 'PACKAGE-MANAGER',
                    'referenceLocator': PackageURL.from_string(purl_ver).to_string(),
                    'referenceType': 'purl'
                }
            ],
            'checksums': [
                {
                    'algorithm': 'MD5',
                    'checksumValue': comp.get('url_hash') or '0' * 32
                }
            ],
        }

    def _process_package_licenses(self, licenses: list, lic_refs: set) -> str:
        """
           Process licenses and return license text formatted for SPDX.

           This method processes a list of license objects, extracts valid license IDs,
           converts them to SPDX format, and combines them into a properly formatted
           license expression.

           Args:
               licenses (list): List of license dictionaries, each containing at least
                               an 'id' field
               lic_refs (set): Reference to a set that will collect license references.
                              This set is modified in place.

           Returns:
               str: A formatted license expression string following SPDX syntax.
                    Returns 'NOASSERTION' if no valid licenses are found.
        """
        if not licenses:
            return 'NOASSERTION'

        lic_set = set()
        for lic in licenses:
            lc_id = lic.get('id')
            self._process_license_id(lc_id, lic_refs, lic_set)

        return self._format_license_text(lic_set)

    def _process_license_id(self, lc_id: str, lic_refs: set, lic_set: set):
        """
         Process individual license ID and add to appropriate sets.

         This method attempts to convert a license ID to its SPDX equivalent.
         If not found in the SPDX license list, it's formatted as a LicenseRef
         and added to the license references set.

         Args:
             lc_id (str): The license ID to process
             lic_refs (set): Reference to a set that collects license references
                            for later processing. Modified in place.
             lic_set (set): Reference to a set collecting all license IDs for
         """
        spdx_id = self.get_spdx_license_id(lc_id)
        if not spdx_id:
            if not lc_id.startswith('LicenseRef'):
                lc_id = f'LicenseRef-{lc_id}'
            lic_refs.add(lc_id)
        lic_set.add(spdx_id if spdx_id else lc_id)

    def _format_license_text(self, lic_set: set) -> str:
        """
            Format the license text with proper SPDX syntax.

            This method combines multiple license IDs with the 'AND' operator
            according to SPDX specification rules. If multiple licenses are present,
            the expression is enclosed in parentheses.

            Args:
                lic_set (set): Set of license IDs to format

            Returns:
                str: A properly formatted SPDX license expression.
                     Returns 'NOASSERTION' if the set is empty.
        """
        if not lic_set:
            return 'NOASSERTION'

        lic_text = ' AND '.join(lic_set)
        if len(lic_set) > 1:
            lic_text = f'({lic_text})'
        return lic_text

    def _process_license_refs(self, lic_refs: set, spdx_document: dict):
        """
            Process and add license references to the SPDX document.

            This method processes each license reference in the provided set
            and adds corresponding license information to the SPDX document's
            extracted licensing information section.

            Args:
                lic_refs (set): Set of license references to process
                spdx_document (dict): Reference to the SPDX document being built,
                                     which will be modified in place

            Note:
                This method modifies the spdx_document dictionary in place by adding
                entries to the 'hasExtractedLicensingInfos' list.
        """
        for lic_ref in lic_refs:
            license_info = self._parse_license_ref(lic_ref)
            spdx_document['hasExtractedLicensingInfos'].append(license_info)

    def _parse_license_ref(self, lic_ref: str) -> dict:
        """
            Parse license reference and create info dictionary for SPDX document.

            This method extracts information from a license reference identifier
            and formats it into the structure required by the SPDX specification
            for extracted licensing information.

            Args:
                lic_ref (str): License reference identifier to parse

            Returns:
                dict: Dictionary containing required SPDX fields for extracted license info:
                      - licenseId: The unique identifier for this license
                      - name: A readable name for the license
                      - extractedText: A placeholder for the actual license text
                      - comment: Information about how the license was detected
        """
        source, name = self._extract_license_info(lic_ref)
        source_text = f' by {source}.' if source else '.'

        return {
            'licenseId': lic_ref,
            'name': name.replace('-', ' '),
            'extractedText': 'Detected license, please review component source code.',
            'comment': f'Detected license{source_text}',
        }

    def _extract_license_info(self, lic_ref: str):
        """
            Extract source and name from license reference.

            This method parses a license reference string to extract the source
            (e.g., scancode, scanoss) and the actual license name using regular
            expressions.

            Args:
                lic_ref (str): License reference identifier to parse

            Returns:
                tuple: A tuple containing (source, name) where:
                       - source (str): The tool or system that identified the license
                       - name (str): The actual license name
        """
        match = re.search(r'^LicenseRef-(scancode-|scanoss-|)(\S+)$', lic_ref, re.IGNORECASE)
        if match:
            source = match.group(1).replace('-', '')
            name = match.group(2)
        else:
            source = ''
            name = lic_ref
        return source, name

    def _write_output(self, data: dict, output_file: str = None) -> bool:
        """Write the SPDX document to output."""
        try:
            file = self._get_output_file(output_file)
            print(json.dumps(data, indent=2), file=file)
            if output_file:
                file.close()
            return True
        except Exception as e:
            self.print_stderr(f'Error writing output: {str(e)}')
            return False

    def _get_output_file(self, output_file: str = None):
        """Get the appropriate output file handle."""
        if not output_file and self.output_file:
            output_file = self.output_file
        return open(output_file, 'w') if output_file else sys.stdout

    def produce_from_str(self, json_str: str, output_file: str = None) -> bool:
        """
        Produce SPDX Lite output from input JSON string
        :param json_str: input JSON string
        :param output_file: Output file (optional)
        :return: True if successful, False otherwise
        """
        if not json_str:
            self.print_stderr('ERROR: No JSON string provided to parse.')
            return False
        try:
            data = json.loads(json_str)
        except Exception as e:
            self.print_stderr(f'ERROR: Problem parsing input JSON: {e}')
            return False
        return self.produce_from_json(data, output_file)

    def load_license_data(self) -> None:
        """
        Load the embedded SPDX valid license JSON files
        Parse its contents to provide a lookup for valid name
        """
        # SPDX license files details from: https://spdx.org/licenses/
        # Specifically the JSON files come from GitHub: https://github.com/spdx/license-list-data/tree/master/json
        self._spdx_licenses = {}
        self._spdx_lic_names = {}
        self.print_debug('Loading SPDX License details...')
        self.load_license_data_file('data/spdx-licenses.json')
        self.load_license_data_file('data/spdx-exceptions.json', 'licenseExceptionId')

    def load_license_data_file(self, filename: str, lic_field: str = 'licenseId') -> bool:
        """
        Load the embedded SPDX valid license JSON file
        Parse its contents to provide a lookup for valid name
        :param filename: license data file to load
        :param lic_field: license id field name (default: licenseId)
        :return: True if successful, False otherwise
        """
        try:
            f_name = importlib_resources.files(__name__) / filename
            with importlib_resources.as_file(f_name) as f:
                with open(f, 'r', encoding='utf-8') as file:
                    data = json.load(file)
        except Exception as e:
            self.print_stderr(f'ERROR: Problem parsing SPDX license input JSON: {e}')
            return False
        else:
            licenses = data.get('licenses')
            if licenses:
                for lic in licenses:
                    lic_name = re.sub('\\s+', '', lic.get('name')).lower()
                    lic_id = lic.get(lic_field)
                    if lic_id:
                        lic_id_lc = lic_id.lower()
                        self._spdx_licenses[lic_id_lc] = lic_id
                        lic_id_short = (lic_id_lc.split('-'))[0]  # extract the name minus the version (i.e. SSPL-1.0)
                        if lic_id_lc != lic_id_short and not self._spdx_licenses.get(lic_id_short):
                            self._spdx_licenses[lic_id_short] = lic_id
                    if lic_name:
                        self._spdx_lic_names[lic_name] = lic_id
        return True

    def get_spdx_license_id(self, lic_name: str) -> str:
        """
        Get the SPDX License ID if possible
        :param lic_name: license name or id
        :return: SPDX license identifier or None
        """
        if not lic_name:
            return None
        search_name_no_spaces = re.sub('\\s+', '', lic_name).lower()  # Remove spaces and lowercase the name
        search_name_dashes = re.sub('\\s+', '-', lic_name).lower()  # Replace spaces with dashes and lowercase
        lic_id = self._spdx_licenses.get(search_name_no_spaces)  # Lookup based on license id
        if lic_id:
            return lic_id
        lic_id = self._spdx_licenses.get(search_name_dashes)
        if lic_id:
            return lic_id
        lic_id = self._spdx_lic_names.get(search_name_no_spaces)  # Lookup based on license name
        if lic_id:
            return lic_id
        lic_id = self._spdx_lic_names.get(search_name_dashes)
        if lic_id:
            return lic_id
        self.print_debug(f'Warning: Failed to find valid SPDX license identifier for: {lic_name}')
        return None


#
# End of SpdxLite Class
#
