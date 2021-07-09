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
import logging
import os
import sys
import time
from json.decoder import JSONDecodeError
import requests
import uuid
import http.client as http_client

DEFAULT_URL      = "https://osskb.org/api/scan/direct"
SCANOSS_SCAN_URL = os.environ.get("SCANOSS_SCAN_URL") if os.environ.get("SCANOSS_SCAN_URL") else DEFAULT_URL
SCANOSS_API_KEY  = os.environ.get("SCANOSS_API_KEY")  if os.environ.get("SCANOSS_API_KEY")  else ''


class ScanossApi:
    """
    ScanOSS REST API client class
    """
    def __init__(self, scan_type: str = None, sbom_path: str = None, scan_format: str = None, flags: str = None,
                 url: str = None, api_key: str = None, debug: bool = False, trace: bool = False, quiet: bool = False):
        """

        """
        self.quiet = quiet
        self.debug = debug
        self.trace = trace
        self.url = url if url else SCANOSS_SCAN_URL
        self.api_key = api_key
        self.scan_type = scan_type
        self.sbom_path = sbom_path
        self.scan_format = scan_format if scan_format else 'plain'
        self.flags = flags
        self.headers = {}
        if self.api_key:
            self.headers['X-Session'] = self.api_key
        self.sbom = None
        self.load_sbom()     # Load an input SBOM if one is specified
        if self.trace:
            logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
            http_client.HTTPConnection.debuglevel = 1

    def load_sbom(self):
        """
        Load the input SBOM if one exists
        """
        if self.sbom_path:
            if not self.scan_type:
                self.scan_type = 'identify'  # Default to the identify SBOM type if it's not set
            self.print_debug(f'Loading {self.scan_type} SBOM {self.sbom_path}...')
            with open(self.sbom_path) as f:
                self.sbom = f.read()

    def scan(self, wfp: str, context: str = None):
        """

        """
        form_data = {}
        if self.sbom:
            form_data['type'] = self.scan_type
            form_data['assets'] = self.sbom
        if self.scan_format:
            form_data['format'] = self.scan_format
        if self.flags:
            form_data['flags'] = self.flags
        if context:
            form_data['context'] = context
        scan_files = {'file': ("%s.wfp" % uuid.uuid1().hex, wfp)}
        r     = None
        retry = 0    # Add some retry logic to cater for timeouts, etc.
        while retry <= 5:
            retry += 1
            try:
                r = None
                r = requests.post(self.url, files=scan_files, data=form_data, headers=self.headers, timeout=120)
            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
                if retry > 5:   # Timed out 5 or more times, fail
                    self.print_stderr(f'ERROR: Timeout/Connection Error POSTing data: {scan_files}')
                    raise Exception(f"ERROR: The SCANOSS API request timed out for {self.url}") from e
                else:
                    self.print_stderr(f'Warning: Timeout/Connection Error communicating with {self.url}. Retrying...')
                    time.sleep(5)
            except Exception as e:
                self.print_stderr(f'ERROR: Exception POSTing data: {scan_files}')
                raise Exception(f"ERROR: The SCANOSS API request failed for {self.url}") from e
            else:
                if not r:
                    if retry > 5:   # No response 5 or more times, fail
                        raise Exception(f"ERROR: The SCANOSS API request response object is empty for {self.url}")
                    else:
                        self.print_stderr(f'Warning: No response received from {self.url}. Retrying...')
                        time.sleep(5)
                elif r.status_code >= 400:
                    if retry > 5:   # No response 5 or more times, fail
                        raise Exception(f"ERROR: The SCANOSS API returned the following error: HTTP {r.status_code}, {r.text}")
                    else:
                        self.print_stderr(f'Warning: Error response code {r.status_code} from {self.url}. Retrying...')
                        time.sleep(5)
                else:
                    retry = 6
                    break     # Valid response, break out of the retry loop
        # End of while loop
        if not r:
            raise Exception(f"ERROR: The SCANOSS API request response object is empty for {self.url}")
        try:
            if 'xml' in self.scan_format:
                return r.text
            json_resp = r.json()
            return json_resp
        except (JSONDecodeError, Exception) as e:
            self.print_stderr(f'The SCANOSS API returned an invalid JSON: {e}')
            self.print_stderr(f'Ignoring result. Please look in "bad_json.json" for more details.')
            with open('bad_json.json', 'w') as f:
                f.write(r.text)
            return None

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

    def print_trace(self, *args, **kwargs):
        """
        Print trace message if enabled
        """
        if self.trace:
            self.print_stderr(*args, **kwargs)

    @staticmethod
    def print_stderr(*args, **kwargs):
        """
        Print the given message to STDERR
        """
        print(*args, file=sys.stderr, **kwargs)

#
# End of ScanossApi Class
#