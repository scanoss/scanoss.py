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
import datetime

from . import __version__

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
        super().__init__(debug)
        self.output_file = output_file
        self.debug = debug
        self._spdx = SpdxLite(debug=debug)

    def parse(self, data: json):
        """
        Parse the given input (raw/plain) JSON string and return CycloneDX summary
        :param data: json - JSON object
        :return: CycloneDX dictionary, and vulnerability dictionary
        """
        if not data:
            self.print_stderr('ERROR: No JSON data provided to parse.')
            return None, None
        self.print_debug(f'Processing raw results into CycloneDX format...')
        cdx = {}
        vdx = {}
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
                        if licenses:
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
                    fd = {}
                    vulnerabilities = d.get("vulnerabilities")
                    if vulnerabilities:
                        for vuln in vulnerabilities:
                            vuln_id = vuln.get("ID")
                            if vuln_id == '':
                                vuln_id = vuln.get("id")
                            if not vuln_id or vuln_id == '':  # Skip empty ids
                                continue
                            vuln_cve = vuln.get("CVE", '')
                            if vuln_cve == '':
                                vuln_cve = vuln.get("cve", '')
                            if vuln_id.upper().startswith("CPE:"):
                                fd['cpe'] = vuln_id                 # Save the component CPE if we have one
                                if vuln_cve != '':
                                    vuln_id = vuln_cve
                            vd = vdx.get(vuln_id)  # Check if we've already encountered this vulnerability
                            if not vd:
                                vuln_source = vuln.get('source', '').lower()
                                vd = {'cve': vuln_cve,
                                      'source': 'NVD' if vuln_source == 'nvd' else 'GitHub Advisories',
                                      'url': f'https://nvd.nist.gov/vuln/detail/{vuln_cve}' if vuln_source == 'nvd' else f'https://github.com/advisories/{vuln_id}',
                                      'severity': self._sev_lookup(vuln.get('severity', 'unknown').lower()),
                                      'affects': set()
                                      }
                            vd.get('affects').add(purl)
                            vdx[vuln_id] = vd
                    if cdx.get(purl):
                        self.print_debug(f'Component {purl} already stored: {cdx.get(purl)}')
                        continue
                    for field in ['id', 'vendor', 'component', 'version', 'latest']:
                        fd[field] = d.get(field)
                    licenses = d.get('licenses')
                    fdl = []
                    if licenses:
                        for lic in licenses:
                            fdl.append({'id': lic.get("name")})
                    fd['licenses'] = fdl
                    cdx[purl] = fd
        # self.print_stderr(f'VD: {vdx}')
        # self.print_stderr(f'CDX: {cdx}')
        return cdx, vdx

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
        Produce the CycloneDX output from the input data
        :param data: JSON object
        :param output_file: Output file (optional)
        :return: True if successful, False otherwise
        """
        cdx, vdx = self.parse(data)
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
            'metadata': {
                'timestamp': datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                'tools': [
                    {
                        'vendor': 'SCANOSS',
                        'name': 'scanoss-py',
                        'version': __version__,
                    }
                ]
            },
            'components': [],
            'vulnerabilities': []
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
            c_data = {
                'type': 'library',
                'name': comp.get('component'),
                'publisher': comp.get('vendor', ''),
                'version': comp.get('version'),
                'purl': purl,
                'bom-ref': purl,
                'licenses': lic_text
            }
            cpe = comp.get('cpe', '')
            if cpe and cpe != '':
                c_data['cpe'] = cpe
            data['components'].append(c_data)
        # End for loop
        if vdx:
            for vuln_id in vdx:
                vulns = vdx.get(vuln_id)
                if not vulns:
                    continue
                v_source = vulns.get('source')
                affects = []
                for purl in vulns.get('affects'):
                    affects.append({'ref': purl})
                vd = {
                    'id': vuln_id,
                    'source': {'name': v_source, 'url': vulns.get('url')},
                    'ratings': [{'severity': vulns.get('severity', 'unknown')}],
                    'affects': affects
                }
                data['vulnerabilities'].append(vd)
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

    @staticmethod
    def _sev_lookup(value: str):
        """
        Lookup the given severity and return a CycloneDX valid version
        :param value: severity to lookup
        :return: CycloneDX severity
        """
        return {
            'critical': 'critical',
            'high': 'high',
            'medium': 'medium',
            'moderate': 'medium',
            'low': 'low',
            'info': 'info',
            'none': 'none',
            'unknown': 'unknown'
            }.get(value, 'unknown')
#
# End of CycloneDX Class
#
