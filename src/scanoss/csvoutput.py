"""
SPDX-License-Identifier: MIT

  Copyright (c) 2022, SCANOSS

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
import csv
import json
import os.path
import sys

from .scanossbase import ScanossBase


class CsvOutput(ScanossBase):
    """
    CsvOutput management class
    Handle all interaction with CSV formatting
    """

    def __init__(self, debug: bool = False, output_file: str = None):
        """
        Initialise the CsvOutput class
        """
        super().__init__(debug)
        self.output_file = output_file
        self.debug = debug

    # TODO Refactor (fails linter)
    def parse(self, data: json): #noqa PLR0912, PLR0915
        """
        Parse the given input (raw/plain) JSON string and return CSV summary
        :param data: json - JSON object
        :return: CSV dictionary
        """
        if data is None:
            self.print_stderr('ERROR: No JSON data provided to parse.')
            return None
        if len(data) == 0:
            self.print_msg('Warning: Empty scan results provided. Returning empty CSV list.')
            return []
        self.print_debug('Processing raw results into CSV format...')
        csv_dict = []
        row_id = 1
        for f in data:
            file_details = data.get(f)
            # print(f'File: {f}: {file_details}')
            for d in file_details:
                id_details = d.get('id')
                if not id_details or id_details == 'none':
                    continue
                matched = d.get('matched', '')
                lines = d.get('lines', '').replace(',', ';')  # swap comma with semicolon to help basic parsers
                oss_lines = d.get('oss_lines', '').replace(',', ';')
                detected = {}
                if id_details == 'dependency':
                    dependencies = d.get('dependencies')
                    if not dependencies:
                        self.print_stderr(f'Warning: No Dependencies found for {f}: {file_details}')
                        continue
                    for deps in dependencies:
                        detected = {}
                        purl = deps.get('purl')
                        if not purl:
                            self.print_stderr(f'Warning: No PURL found for {f}: {deps}')
                            continue
                        detected['purls'] = purl
                        for field in ['component', 'version', 'latest', 'url']:
                            detected[field] = deps.get(field, '')
                        licenses = deps.get('licenses')
                        dc = []
                        if licenses:
                            for lic in licenses:
                                name = lic.get('name')
                                if name and name not in dc:  # Only save the license name once
                                    dc.append(name)
                        if not dc or len(dc) == 0:
                            detected['licenses'] = ''
                        else:
                            detected['licenses'] = ';'.join(dc)
                        # inventory_id,path,usage,detected_component,detected_license,
                        # detected_version,detected_latest,purl
                        csv_dict.append(
                            {
                                'inventory_id': row_id,
                                'path': f,
                                'detected_usage': id_details,
                                'detected_component': detected.get('component'),
                                'detected_license': detected.get('licenses'),
                                'detected_version': detected.get('version'),
                                'detected_latest': detected.get('latest'),
                                'detected_purls': detected.get('purls'),
                                'detected_url': detected.get('url'),
                                'detected_path': detected.get('file', ''),
                                'detected_match': matched,
                                'detected_lines': lines,
                                'detected_oss_lines': oss_lines,
                            }
                        )
                        row_id = row_id + 1
                else:
                    purls = d.get('purl')
                    if not purls:
                        self.print_stderr(f'Warning: Purl block missing for {f}: {file_details}')
                        continue
                    pa = []
                    for p in purls:
                        self.print_debug(f'Purl: {p}')
                        pa.append(p)
                    if not pa or len(pa) == 0:
                        self.print_stderr(f'Warning: No PURL found for {f}: {file_details}')
                        continue
                    detected['purls'] = ';'.join(pa)
                    for field in ['component', 'version', 'latest', 'url', 'file']:
                        detected[field] = d.get(field, '')
                    licenses = d.get('licenses')
                    dc = []
                    if licenses:
                        for lic in licenses:
                            name = lic.get('name')
                            if name and name not in dc:  # Only save the license name once
                                dc.append(lic.get('name'))
                    if not dc or len(dc) == 0:
                        detected['licenses'] = ''
                    else:
                        detected['licenses'] = ';'.join(dc)
                    # inventory_id,path,usage,detected_component,detected_license,detected_version,detected_latest,purl
                    csv_dict.append(
                        {
                            'inventory_id': row_id,
                            'path': f,
                            'detected_usage': id_details,
                            'detected_component': detected.get('component'),
                            'detected_license': detected.get('licenses'),
                            'detected_version': detected.get('version'),
                            'detected_latest': detected.get('latest'),
                            'detected_purls': detected.get('purls'),
                            'detected_url': detected.get('url'),
                            'detected_path': detected.get('file', ''),
                            'detected_match': matched,
                            'detected_lines': lines,
                            'detected_oss_lines': oss_lines,
                        }
                    )
                    row_id = row_id + 1
        return csv_dict

    def produce_from_file(self, json_file: str, output_file: str = None) -> bool:
        """
        Parse plain/raw input JSON file and produce CSV output
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
        Produce the CSV output from the input data
        :param data: JSON object
        :param output_file: Output file (optional)
        :return: True if successful, False otherwise
        """
        csv_data = self.parse(data)
        if csv_data is None:
            self.print_stderr('ERROR: No CSV data returned for the JSON string provided.')
            return False
        if len(csv_data) == 0:
            self.print_msg('Warning: Empty scan results - generating CSV with headers only.')
        # Header row/column details
        fields = [
            'inventory_id',
            'path',
            'detected_usage',
            'detected_component',
            'detected_license',
            'detected_version',
            'detected_latest',
            'detected_purls',
            'detected_url',
            'detected_match',
            'detected_lines',
            'detected_oss_lines',
            'detected_path',
        ]
        file = sys.stdout
        if not output_file and self.output_file:
            output_file = self.output_file
        if output_file:
            file = open(output_file, 'w')
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()  # writing headers (field names)
        writer.writerows(csv_data)  # writing data rows
        if output_file:
            file.close()

        return True

    def produce_from_str(self, json_str: str, output_file: str = None) -> bool:
        """
        Produce CSV output from input JSON string
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
# End of CsvOutput Class
#
