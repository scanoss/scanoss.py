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
import json
import os.path
import sys
import hashlib
import datetime
import getpass
import re
import pkg_resources

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
        self.print_debug(f'Processing raw results into summary format...')
        summary = {}
        for f in data:
            file_details = data.get(f)
            # print(f'File: {f}: {file_details}\n')
            for d in file_details:
                id_details = d.get("id")
                if not id_details or id_details == 'none':  # Ignore files with no ids
                    continue
                purl = None
                if id_details == 'dependency':  # Process dependency data
                    dependencies = d.get("dependencies")
                    if not dependencies:
                        self.print_stderr(f'Warning: No Dependencies found for {f}: {file_details}')
                        continue
                    for deps in dependencies:
                        # print(f'File: {f} Deps: {deps}')
                        purl = deps.get("purl")
                        if not purl:
                            self.print_stderr(f'Warning: No PURL found for {f}: {deps}')
                            continue
                        if summary.get(purl):
                            self.print_debug(f'Component {purl} already stored: {summary.get(purl)}')
                            continue
                        fd = {}
                        for field in ['component', 'version', 'url']:
                            fd[field] = deps.get(field, '')
                        licenses = deps.get('licenses')
                        fdl = []
                        dc = []
                        for lic in licenses:
                            name = lic.get("name")
                            if name not in dc:  # Only save the license name once
                                fdl.append({'id': name})
                                dc.append(name)
                        fd['licenses'] = fdl
                        summary[purl] = fd
                else:  # Normal file id type
                    purls = d.get('purl')
                    if not purls:
                        self.print_stderr(f'Purl block missing for {f}: {file_details}')
                        continue
                    for p in purls:
                        self.print_debug(f'Purl: {p}')
                        purl = p
                        break
                    if not purl:
                        self.print_stderr(f'Warning: No PURL found for {f}: {file_details}')
                        continue
                    if summary.get(purl):
                        self.print_debug(f'Component {purl} already stored: {summary.get(purl)}')
                        continue
                    fd = {}
                    for field in ['id', 'vendor', 'component', 'version', 'latest', 'url']:
                        fd[field] = d.get(field)
                    licenses = d.get('licenses')
                    fdl = []
                    dc = []
                    for lic in licenses:
                        name = lic.get("name")
                        if name not in dc:  # Only save the license name once
                            fdl.append({'id': name})
                            dc.append(name)
                    fd['licenses'] = fdl
                    summary[purl] = fd
        return summary

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
        Produce the SPDX Lite output from the input JSON object
        :param data: JSON object
        :param output_file: Output file (optional)
        :return: True if successful, False otherwise
        """
        raw_data = self.parse(data)
        if not raw_data:
            self.print_stderr('ERROR: No SPDX data returned for the JSON string provided.')
            return False
        self.load_license_data()
        # Using this SPDX version as the spec
        # https://github.com/spdx/spdx-spec/blob/development/v2.2.2/examples/SPDXJSONExample-v2.2.spdx.json
        # Validate using:
        # pip3 install jsonschema
        # jsonschema -i spdxlite.json  <(curl https://raw.githubusercontent.com/spdx/spdx-spec/v2.2/schemas/spdx-schema.json)
        # Validation can also be done online here: https://tools.spdx.org/app/validate/
        now = datetime.datetime.utcnow()
        md5hex = hashlib.md5(f'{raw_data}-{now}'.encode('utf-8')).hexdigest()
        data = {
            'spdxVersion': 'SPDX-2.2',
            'dataLicense': 'CC0-1.0',
            'SPDXID': f'SPDXRef-{md5hex}',
            'name': 'SCANOSS-SBOM',
            'creationInfo': {
                'created': now.strftime('%Y-%m-%dT%H:%M:%S') + now.strftime('.%f')[:4] + 'Z',
                'creators': [f'Tool: SCANOSS-PY: {__version__}', f'Person: {getpass.getuser()}']
            },
            'documentNamespace': f'https://spdx.org/spdxdocs/scanoss-py-{__version__}-{md5hex}',
            'packages': []
        }
        for purl in raw_data:
            comp = raw_data.get(purl)
            lic_names = []
            licenses = comp.get('licenses')
            lic_text = 'NOASSERTION'
            if licenses:
                for lic in licenses:
                    lc_id = lic.get('id')
                    if lc_id:
                        spdx_id = self.get_spdx_license_id(lc_id)
                        lic_names.append(spdx_id if spdx_id else lc_id)
                if len(lic_names) > 0:
                    lic_text = ' AND '.join(lic_names)
                if len(lic_names) > 1:
                    lic_text = f'({lic_text})'  # wrap the names in () if there is more than one
            comp_name = comp.get('component')
            comp_ver = comp.get('version')
            purl_ver = f'{purl}@{comp_ver}'
            purl_hash = hashlib.md5(f'{purl_ver}'.encode('utf-8')).hexdigest()
            data['packages'].append({
                'name': comp_name,
                'SPDXID': f'SPDXRef-{purl_hash}',
                'versionInfo': comp_ver,
                'downloadLocation': 'NOASSERTION',  # TODO Add actual download location
                'homepage': comp.get('url', ''),
                'licenseDeclared': lic_text,
                'licenseConcluded': 'NOASSERTION',
                'filesAnalyzed': False,
                'copyrightText': 'NOASSERTION',
                'externalRefs': [{
                    'referenceCategory': 'PACKAGE_MANAGER',
                    'referenceLocator': purl_ver,
                    'referenceType': 'purl'
                }]
            })
        # End for loop
        file = sys.stdout
        if not output_file and self.output_file:
            output_file = self.output_file
        if output_file:
            file = open(output_file, 'w')
        print(json.dumps(data, indent=2), file=file)
        if output_file:
            file.close()
        return True

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
            f_name = pkg_resources.resource_filename(__name__, filename)
            with open(f_name, 'r') as f:
                data = json.loads(f.read())
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
        self.print_stderr(f'Warning: Failed to find valid SPDX license identifier for: {lic_name}')
        return None
#
# End of SpdxLite Class
#
