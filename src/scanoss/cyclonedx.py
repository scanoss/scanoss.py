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
import sys


class CycloneDx:
    """

    """
    def __init__(self, output_file: str = None):
        """

        """
        self.output_file = output_file

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

    def parse(self, json_str: str):
        """

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
                        print(f'Purl block missing for {f}: {file_details}')
                        continue
                    for p in purls:
                        print(f'Purl: {p}')
                        purl = p
                        break
                    if not purl:
                        print(f'Warning: No PURL found for {f}: {file_details}')
                        continue
                    if cdx.get(purl):
                        print(f'Component {purl} already stored: {cdx.get(purl)}')
                        continue
                    fd = {}
                    print(f'Vendor: {d.get("vendor")}, Comp: {d.get("component")}, Ver: {d.get("version")},'
                          f' Latest: {d.get("latest")}')
                    for field in ['vendor', 'component', 'version', 'latest']:
                        fd[field] = d.get(field)
                    licenses = d.get('licenses')
                    for lic in licenses:
                        print(f'License: {lic.get("name")}')
                        fd['license'] = lic.get("name")
                        break
                    cdx[p] = fd
            print(f'License summary: {cdx}')
            return cdx

    def produce(self, json_str: str, output_file: str):
        """

        """
        if not json_str:
            self.print_stderr('ERROR: No JSON string provided to parse.')
            return
        cdx = (self, json_str)


#
# End of CycloneDX Class
#


def main():
    """
    Local test of the CycloneDX class
    """
    print('Testing CycloneDx...')
    cdx = CycloneDx()


if __name__ == "__main__":
    main()
