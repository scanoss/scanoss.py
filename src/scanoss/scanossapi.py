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
import logging
import os
import sys
import time
from json.decoder import JSONDecodeError
import requests
import uuid
import http.client as http_client
import urllib3

from urllib3.exceptions import InsecureRequestWarning
from .scanossbase import ScanossBase

DEFAULT_URL = "https://osskb.org/api/scan/direct"  # default free service URL
DEFAULT_URL2 = "https://scanoss.com/api/scan/direct"  # default premium service URL
SCANOSS_SCAN_URL = os.environ.get("SCANOSS_SCAN_URL") if os.environ.get("SCANOSS_SCAN_URL") else DEFAULT_URL
SCANOSS_API_KEY = os.environ.get("SCANOSS_API_KEY") if os.environ.get("SCANOSS_API_KEY") else ''


class ScanossApi(ScanossBase):
    """
    ScanOSS REST API client class
    Currently support posting scan requests to the SCANOSS streaming API
    """

    def __init__(self, scan_type: str = None, sbom_path: str = None, scan_format: str = None, flags: str = None,
                 url: str = None, api_key: str = None, debug: bool = False, trace: bool = False, quiet: bool = False,
                 timeout: int = 120, ver_details: str = None, ignore_cert_errors: bool = False,
                 proxy: str = None, ca_cert: str = None):
        """
        Initialise the SCANOSS API
        :param scan_type: Scan type (default identify)
        :param sbom_path: Input SBOM file to match scan type (default None)
        :param scan_format: Scan format (default plain)
        :param flags: Scanning flags (default None)
        :param url: API URL (default https://osskb.org/api/scan/direct)
        :param api_key: API Key (default None)
        :param debug: Enable debug (default False)
        :param trace: Enable trace (default False)
        :param quiet: Enable quite mode (default False)

        To set a custom certificate use:
            REQUESTS_CA_BUNDLE=/path/to/cert.pem
        To enable a Proxy use:
            HTTP_PROXY='http://<ip>:<port>'
            HTTPS_PROXY='http://<ip>:<port>'
        """
        super().__init__(debug, trace, quiet)
        self.url = url if url else SCANOSS_SCAN_URL
        self.api_key = api_key if api_key else SCANOSS_API_KEY
        if self.api_key and not url and not os.environ.get("SCANOSS_SCAN_URL"):
            self.url = DEFAULT_URL2  # API key specific and no alternative URL, so use the default premium
        self.scan_type = scan_type
        self.scan_format = scan_format if scan_format else 'plain'
        self.sbom_path = sbom_path
        self.flags = flags
        self.timeout = timeout if timeout > 5 else 120
        self.ignore_cert_errors = ignore_cert_errors
        self.headers = {}
        if ver_details:
            self.headers['x-scanoss-client'] = ver_details
        if self.api_key:
            self.headers['X-Session'] = self.api_key
            self.headers['x-api-key'] = self.api_key
        self.sbom = None
        self.load_sbom()  # Load an input SBOM if one is specified
        if self.trace:
            logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
            http_client.HTTPConnection.debuglevel = 1
        self.verify = None
        if self.ignore_cert_errors:
            self.print_debug(f'Ignoring cert errors...')
            urllib3.disable_warnings(InsecureRequestWarning)
            self.verify = False
        elif ca_cert:
            self.verify = ca_cert
        self.proxies = {'https': proxy, 'http': proxy} if proxy else None

    def load_sbom(self):
        """
        Load the input SBOM if one exists
        """
        if self.sbom_path:
            if not self.scan_type:
                self.scan_type = 'identify'  # Default to identify SBOM type if it's not set
            self.print_debug(f'Loading {self.scan_type} SBOM {self.sbom_path}...')
            with open(self.sbom_path) as f:
                self.sbom = f.read()

    def scan(self, wfp: str, context: str = None, scan_id: int = None):
        """
        Scan the specified WFP and return the JSON object
        :param wfp: WFP to scan
        :param context: Context to help with identification
        :param scan_id: ID of the scan being run (usually thread id)
        :return: JSON result object
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
        r = None
        retry = 0  # Add some retry logic to cater for timeouts, etc.
        while retry <= 5:
            retry += 1
            try:
                r = None
                r = requests.post(self.url, files=scan_files, data=form_data, headers=self.headers,
                                  timeout=self.timeout, verify=self.verify, proxies=self.proxies
                                  )
            except (requests.exceptions.SSLError, requests.exceptions.ProxyError) as e:
                self.print_stderr(f'ERROR: Exception ({e.__class__.__name__}) POSTing data - {e}.')
                raise Exception(f"ERROR: The SCANOSS API request failed for {self.url}") from e
            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
                if retry > 5:  # Timed out 5 or more times, fail
                    self.print_stderr(f'ERROR: {e.__class__.__name__} POSTing data - {e}: {scan_files}')
                    raise Exception(f"ERROR: The SCANOSS API request timed out ({e.__class__.__name__}) for {self.url}") from e
                else:
                    self.print_stderr(f'Warning: {e.__class__.__name__} communicating with {self.url}. Retrying...')
                    time.sleep(5)
            except Exception as e:
                self.print_stderr(f'ERROR: Exception ({e.__class__.__name__}) POSTing data - {e}: {scan_files}')
                raise Exception(f"ERROR: The SCANOSS API request failed for {self.url}") from e
            else:
                if not r:
                    if retry > 5:  # No response 5 or more times, fail
                        raise Exception(f"ERROR: The SCANOSS API request response object is empty for {self.url}")
                    else:
                        self.print_stderr(f'Warning: No response received from {self.url}. Retrying...')
                        time.sleep(5)
                elif r.status_code >= 400:
                    if retry > 5:  # No response 5 or more times, fail
                        raise Exception(
                            f"ERROR: The SCANOSS API returned the following error: HTTP {r.status_code}, {r.text}")
                    else:
                        self.print_stderr(f'Warning: Error response code {r.status_code} from {self.url}. Retrying...')
                        time.sleep(5)
                else:
                    break  # Valid response, break out of the retry loop
        # End of while loop
        if not r:
            raise Exception(f"ERROR: The SCANOSS API request response object is empty for {self.url}")
        try:
            if 'xml' in self.scan_format:
                return r.text
            json_resp = r.json()
            return json_resp
        except (JSONDecodeError, Exception) as e:
            self.print_stderr(f'ERROR: The SCANOSS API returned an invalid JSON ({e.__class__.__name__}): {e}')
            ctime = int(time.time())
            bad_json_file = f'bad_json-{scan_id}-{ctime}.txt' if scan_id else f'bad_json-{ctime}.txt'
            self.print_stderr(f'Ignoring result. Please look in "{bad_json_file}" for more details.')
            try:
                with open(bad_json_file, 'w') as f:
                    f.write(f"---WFP Begin---\n{scan_files}\n---WFP End---\n---Bad JSON Begin---\n")
                    f.write(r.text)
                    f.write("---Bad JSON End---\n")
            except Exception as ee:
                self.print_stderr(f'Warning: Issue writing bad json file - {bad_json_file} ({ee.__class__.__name__}):'
                                  f' {ee}')
            return None

#
# End of ScanossApi Class
#
