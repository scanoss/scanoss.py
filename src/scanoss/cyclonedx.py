"""
 SPDX-License-Identifier: GPL-2.0-or-later

   Copyright (C) 2018-2021 SCANOSS LTD

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""
import json
import os.path
import sys
import hashlib
import time


class CycloneDx:
    """

    """
    def __init__(self, debug: bool = False, output_file: str = None):
        """

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

    def parse_file(self, file: str):
        """
        Parse the given input (raw/plain) JSON file and return CycloneDX summary

        :param file: str - JSON file to parse
        :return: CycloneDX dictionary
        """
        if not file:
            self.print_stderr('ERROR: No JSON file provided to parse.')
            return None
        if not os.path.isfile(file):
            self.print_stderr('ERROR: JSON file does not exist or is not a file.')
            return None
        with open(file) as f:
            return self.parse(f.read())


    def parse(self, json_str: str):
        """
        Parse the given input (raw/plain) JSON string and return CycloneDX summary

        :param json_str: str - JSON string
        :return: CycloneDX dictionary
        """
        if not json_str:
            self.print_stderr('ERROR: No JSON string provided to parse.')
            return None
        self.print_debug(f'Processing raw results into CycloneDX format...')
        results = json.loads(json_str)
        cdx = {}
        if results:
            for f in results:
                file_details = results.get(f)
                # print(f'File: {f}: {file_details}')
                for d in file_details:
                    id_details = d.get("id")
                    if not id_details or id_details == 'none':
                        # print(f'No ID for {f}')
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
                    if cdx.get(purl):
                        self.print_debug(f'Component {purl} already stored: {cdx.get(purl)}')
                        continue
                    fd = {}
                    # print(f'Vendor: {d.get("vendor")}, Comp: {d.get("component")}, Ver: {d.get("version")},'
                    #       f' Latest: {d.get("latest")} ID: {d.get("id")}')
                    for field in ['id', 'vendor', 'component', 'version', 'latest']:
                        fd[field] = d.get(field)
                    licenses = d.get('licenses')
                    fdl = []
                    for lic in licenses:
                        # print(f'License: {lic.get("name")}')
                        fdl.append({'id':lic.get("name")})
                    fd['licenses'] = fdl
                    cdx[p] = fd
            # print(f'License summary: {cdx}')
            return cdx

    def produce_from_file(self, json_file: str, output_file: str = None):
        """


        :param json_file:
        :param output_file:
        :return:
        """
        if not json_file:
            self.print_stderr('ERROR: No JSON file provided to parse.')
            return None
        if not os.path.isfile(json_file):
            self.print_stderr(f'ERROR: JSON file does not exist or is not a file: {json_file}')
            return None
        with open(json_file, 'r') as f:
            self.produce_from_str(f.read(), output_file)


    def produce_from_str(self, json_str: str, output_file: str = None):
        """

        :param json_str:
        :param output_file:
        :return:
        """
        if not json_str:
            self.print_stderr('ERROR: No JSON string provided to parse.')
            return
        cdx = self.parse(json_str)
        if not cdx:
            self.print_stderr('ERROR: No CycloneDX data returned for the JSON string provided.')
            return
        md5hex = hashlib.md5(f'{time.time()}'.encode('utf-8')).hexdigest()
        data = {}
        data['bomFormat'] = 'CycloneDX'
        data['specVersion'] = '1.2'
        data['serialNumber'] = f'scanoss:SCANOSS-PY - SCANOSS CLI-{md5hex}'
        data['version'] = '1'
        data['components'] = []
        for purl in cdx:
            comp = cdx.get(purl)
            lic = []
            licenses = comp.get('licenses')
            if licenses:
                for l in licenses:
                    lic.append({'license': { 'id': l.get('id')}})
            m_type = 'Snippet' if comp.get('id') == 'snippet' else 'Library'
            data['components'].append({
                'type': m_type,
                'name': comp.get('component'),
                'publisher': comp.get('vendor'),
                'version': comp.get('version'),
                'purl': purl,
                'licenses': lic
                # 'licenses': [{
                #     'license': {
                #         'id': comp.get('license')
                #     }
                # }]
            })

        file = sys.stdout
        if not output_file and self.output_file:
            output_file = self.output_file
        if output_file:
            file = open(output_file, 'w')
        print(json.dumps(data, indent=2), file=file)
        if output_file:
            file.close()

#
# End of CycloneDX Class
#


def main():
    """
    Local test of the CycloneDX class
    """
    print('Testing CycloneDx...')
    cdx = CycloneDx()

    cdx.produce_from_file('scan_output.json')


if __name__ == "__main__":
    main()
