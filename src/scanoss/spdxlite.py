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
        if not data:
            self.print_stderr('ERROR: No JSON data provided to parse.')
            return None

        self.print_debug('Processing raw results into summary format...')
        return self._process_files(data)

    def _process_files(self, data: json) -> dict:
        """Process each file in the data and build summary."""
        summary = {}
        for file_path in data:
            file_details = data.get(file_path)
            self._process_file_entries(file_path, file_details, summary)
        return summary

    def _process_file_entries(self, file_path: str, file_details: list, summary: dict):
        """Process entries for a single file."""
        for entry in file_details:
            id_details = entry.get('id')
            if not id_details or id_details == 'none':
                continue

            if id_details == 'dependency':
                self._process_dependency_entry(file_path, entry, summary)
            else:
                self._process_normal_entry(file_path, entry, summary)

    def _process_dependency_entry(self, file_path: str, entry: dict, summary: dict):
        """Process a dependency type entry."""
        dependencies = entry.get('dependencies')
        if not dependencies:
            self.print_stderr(f'Warning: No Dependencies found for {file_path}')
            return

        for dep in dependencies:
            purl = dep.get('purl')
            if not self._is_valid_purl(file_path, dep, purl, summary):
                continue

            summary[purl] = self._create_dependency_summary(dep)

    def _process_normal_entry(self, file_path: str, entry: dict, summary: dict):
        """Process a normal file type entry."""
        purls = entry.get('purl')
        if not purls:
            self.print_stderr(f'Purl block missing for {file_path}')
            return

        purl = purls[0] if purls else None
        if not self._is_valid_purl(file_path, entry, purl, summary):
            return

        summary[purl] = self._create_normal_summary(entry)

    def _is_valid_purl(self, file_path: str, entry: dict, purl: str, summary: dict) -> bool:
        """Check if PURL is valid and not already processed."""
        if not purl:
            self.print_stderr(f'Warning: No PURL found for {file_path}: {entry}')
            return False

        if summary.get(purl):
            self.print_debug(f'Component {purl} already stored: {summary.get(purl)}')
            return False

        return True

    def _create_dependency_summary(self, dep: dict) -> dict:
        """Create summary for dependency entry."""
        summary = {}
        for field in ['component', 'version', 'url']:
            summary[field] = dep.get(field, '')
        summary['licenses'] = self._process_licenses(dep.get('licenses'))
        return summary

    def _create_normal_summary(self, entry: dict) -> dict:
        """Create summary for normal file entry."""
        summary = {}
        fields = ['id', 'vendor', 'component', 'version', 'latest',
                  'url', 'url_hash', 'download_url']
        for field in fields:
            summary[field] = entry.get(field)
        summary['licenses'] = self._process_licenses(entry.get('licenses'))
        return summary

    def _process_licenses(self, licenses: list) -> list:
        """Process license information and remove duplicates."""
        if not licenses:
            return []

        processed_licenses = []
        seen_names = set()

        for license_info in licenses:
            name = license_info.get('name')
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
        if not raw_data:
            self.print_stderr('ERROR: No SPDX data returned for the JSON string provided.')
            return False

        self.load_license_data()
        spdx_document = self._create_base_document(raw_data)
        self._process_packages(raw_data, spdx_document)
        return self._write_output(spdx_document, output_file)

    def _create_base_document(self, raw_data: dict) -> dict:
        """Create the base SPDX document structure."""
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
        """Create the creation info section."""
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
        """Process packages and add them to the SPDX document."""
        lic_refs = set()

        for purl, comp in raw_data.items():
            package_info = self._create_package_info(purl, comp, lic_refs)
            spdx_document['packages'].append(package_info)
            spdx_document['documentDescribes'].append(package_info['SPDXID'])

        self._process_license_refs(lic_refs, spdx_document)

    def _create_package_info(self, purl: str, comp: dict, lic_refs: set) -> dict:
        """Create package information for SPDX document."""
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
                    'referenceLocator': purl_ver,
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
        """Process licenses and return license text."""
        if not licenses:
            return 'NOASSERTION'

        lic_set = set()
        for lic in licenses:
            lc_id = lic.get('id')
            if lc_id:
                self._process_license_id(lc_id, lic_refs, lic_set)

        return self._format_license_text(lic_set)

    def _process_license_id(self, lc_id: str, lic_refs: set, lic_set: set):
        """Process individual license ID."""
        spdx_id = self.get_spdx_license_id(lc_id)
        if not spdx_id:
            if not lc_id.startswith('LicenseRef'):
                lc_id = f'LicenseRef-{lc_id}'
            lic_refs.add(lc_id)
        lic_set.add(spdx_id if spdx_id else lc_id)

    def _format_license_text(self, lic_set: set) -> str:
        """Format the license text with proper syntax."""
        if not lic_set:
            return 'NOASSERTION'

        lic_text = ' AND '.join(lic_set)
        if len(lic_set) > 1:
            lic_text = f'({lic_text})'
        return lic_text

    def _process_license_refs(self, lic_refs: set, spdx_document: dict):
        """Process and add license references to the document."""
        for lic_ref in lic_refs:
            license_info = self._parse_license_ref(lic_ref)
            spdx_document['hasExtractedLicensingInfos'].append(license_info)

    def _parse_license_ref(self, lic_ref: str) -> dict:
        """Parse license reference and create info dictionary."""
        source, name = self._extract_license_info(lic_ref)
        source_text = f' by {source}.' if source else '.'

        return {
            'licenseId': lic_ref,
            'name': name.replace('-', ' '),
            'extractedText': 'Detected license, please review component source code.',
            'comment': f'Detected license{source_text}',
        }

    def _extract_license_info(self, lic_ref: str):
        """Extract source and name from license reference."""
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
            # self.print_stderr(f'Licenses: {self._spdx_licenses}')
            # self.print_stderr(f'Lookup: {self._spdx_lic_lookup}')
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
