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
import uuid

from .scanossbase import ScanossBase
from .spdxlite import SpdxLite


class CycloneDx(ScanossBase):
    """
    CycloneDX management class
    Handle all interaction with CycloneDX formatting
    """

    def __init__(self, debug: bool = False, output_file: str = None):
        """
        Initialise the CycloneDX class
        """
        self.output_file = output_file
        self.debug = debug
        self._spdx = SpdxLite(debug=debug)

    def parse(self, data: json):
        """
        Parse the given input (raw/plain) JSON string and return CycloneDX summary
        :param data: json - JSON object
        :return: CycloneDX dictionary
        """
        if not data:
            self.print_stderr('ERROR: No JSON data provided to parse.')
            return None
        self.print_debug(f'Processing raw results into CycloneDX format...')
        cdx = {}
        for f in data:
            file_details = data.get(f)
            # print(f'File: {f}: {file_details}')
            for d in file_details:
                id_details = d.get("id")
                if not id_details or id_details == 'none':
                    continue
                purl = None
                if id_details == 'dependency':
                    dependencies = d.get("dependencies")
                    if not dependencies:
                        self.print_stderr(f'Warning: No Dependencies found for {f}: {file_details}')
                        continue
                    for deps in dependencies:
                        purl = deps.get("purl")
                        if not purl:
                            self.print_stderr(f'Warning: No PURL found for {f}: {deps}')
                            continue
                        if cdx.get(purl):
                            self.print_debug(f'Component {purl} already stored: {cdx.get(purl)}')
                            continue
                        fd = {}
                        for field in ['component', 'version']:
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
                        cdx[purl] = fd
                else:
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
                    if cdx.get(purl):
                        self.print_debug(f'Component {purl} already stored: {cdx.get(purl)}')
                        continue
                    fd = {}
                    for field in ['id', 'vendor', 'component', 'version', 'latest']:
                        fd[field] = d.get(field)
                    licenses = d.get('licenses')
                    fdl = []
                    for lic in licenses:
                        fdl.append({'id': lic.get("name")})
                    fd['licenses'] = fdl
                    cdx[purl] = fd
        return cdx

    def produce_from_file(self, json_file: str, output_file: str = None) -> bool:
        """
        Parse plain/raw input JSON file and produce CycloneDX output
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
        Produce the CycloneDX output from the input JSON object
        :param data: JSON object
        :param output_file: Output file (optional)
        :return: True if successful, False otherwise
        """
        cdx = self.parse(data)
        if not cdx:
            self.print_stderr('ERROR: No CycloneDX data returned for the JSON string provided.')
            return False
        self._spdx.load_license_data()  # Load SPDX license name data for later reference
        #
        # Using CDX version 1.4: https://cyclonedx.org/docs/1.4/json/
        # Validate using: https://github.com/CycloneDX/cyclonedx-cli
        # cyclonedx-cli validate --input-format json --input-version v1_4 --fail-on-errors --input-file cdx.json
        #
        data = {
            'bomFormat': 'CycloneDX',
            'specVersion': '1.4',
            'serialNumber': f'urn:uuid:{uuid.uuid4()}',
            'version': 1,
            'components': []
        }
        for purl in cdx:
            comp = cdx.get(purl)
            lic_text = []
            licenses = comp.get('licenses')
            if licenses:
                lic_set = set()
                for lic in licenses:  # Get a unique set of licenses
                    lc_id = lic.get('id')
                    spdx_id = self._spdx.get_spdx_license_id(lc_id)
                    lic_set.add(spdx_id if spdx_id else lc_id)
                for lc_id in lic_set:  # Store licenses for later inclusion
                    spdx_id = self._spdx.get_spdx_license_id(lc_id)
                    if not spdx_id:
                        lic_text.append({'license': {'name': lc_id}})  # Not an SPDX license, so store it by name
                    else:
                        lic_text.append({'license': {'id': spdx_id}})
            m_type = 'library'
            data['components'].append({
                'type': m_type,
                'name': comp.get('component'),
                'publisher': comp.get('vendor', ''),
                'version': comp.get('version'),
                'purl': purl,
                'licenses': lic_text
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
        Produce CycloneDX output from input JSON string
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
#
# End of CycloneDX Class
#
