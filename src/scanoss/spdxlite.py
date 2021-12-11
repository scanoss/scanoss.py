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
import time
import datetime


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

    @staticmethod
    def print_stderr(*args, **kwargs):
        """
        Print the given message to STDERR
        """
        print(*args, file=sys.stderr, **kwargs)

    def print_msg(self, *args, **kwargs):
        """
        Print message if quite mode is not enabled
        """
        if not self.quiet:
            self.print_stderr(*args, **kwargs)

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
            # print(f'File: {f}: {file_details}')
            for d in file_details:
                id_details = d.get("id")
                if not id_details or id_details == 'none':  # Ignore files with no ids
                    continue
                purl = None
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
                    if not name in dc:             # Only save the license name once
                        fdl.append({'id':name})
                        dc.append(name)
                fd['licenses'] = fdl
                summary[p] = fd
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
        success = True
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
        now = datetime.datetime.utcnow()
        md5hex = hashlib.md5(f'{time.time()}'.encode('utf-8')).hexdigest()
        data = {}
        data['spdxVersion'] = 'SPDX-2.2'
        data['dataLicense'] = 'CC0-1.0'
        data['SPDXIdentifier'] = f'SCANOSS-SPDX-{md5hex}'
        data['DocumentName'] = 'SCANOSS-SBOM'
        data['creator'] = 'Tool: SCANOSS-PY'
        data['created'] = now.strftime('%Y-%m-%dT%H:%M:%S') + now.strftime('.%f')[:4] + 'Z'
        data['Packages'] = []
        for purl in raw_data:
            comp = raw_data.get(purl)
            lic = []
            licenses = comp.get('licenses')
            if licenses:
                for l in licenses:
                    lic.append(l.get('id'))
            data['Packages'].append({
                'PackageName': comp.get('component'),
                'PackageSPDXID': purl,
                'PackageVersion': comp.get('version'),
                'PackageDownloadLocation': comp.get('url'),
                'DeclaredLicense': f'({" AND ".join(lic)})' if len(lic) > 0 else ''
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
        data = None
        try:
            data = json.loads(json_str)
        except Exception as e:
            self.print_stderr(f'ERROR: Problem parsing input JSON: {e}')
            return False
        else:
            return self.produce_from_json(data, output_file)
        return False
#
# End of SpdxLite Class
#