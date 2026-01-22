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

import http.client as http_client
import logging
import os
import sys
import time
import uuid
from json.decoder import JSONDecodeError
from urllib.parse import urlparse, urlunparse

import requests
import urllib3
from pypac import PACSession
from pypac.parser import PACFile
from urllib3.exceptions import InsecureRequestWarning

from . import __version__
from .constants import DEFAULT_TIMEOUT, MIN_TIMEOUT
from .scanossbase import ScanossBase

DEFAULT_URL = 'https://api.osskb.org'  # default free service base URL
DEFAULT_URL2 = 'https://api.scanoss.com'  # default premium service base URL
SCAN_ENDPOINT = '/scan/direct'  # scan endpoint path
SCANOSS_SCAN_URL = os.environ.get('SCANOSS_SCAN_URL') if os.environ.get('SCANOSS_SCAN_URL') else DEFAULT_URL
SCANOSS_API_KEY = os.environ.get('SCANOSS_API_KEY') if os.environ.get('SCANOSS_API_KEY') else ''


class ScanossApi(ScanossBase):
    """
    ScanOSS REST API client class
    Currently support posting scan requests to the SCANOSS streaming API
    """

    def normalize_api_url(self, url: str) -> str:
        """
        Normalize API URL to ensure it's a base URL with the scan endpoint appended.

        If the URL contains a path component (e.g., /scan/direct), a warning is emitted
        and the path is stripped to use only the base URL.

        :param url: Input URL (can be base URL or full endpoint URL)
        :return: Normalized URL with /scan/direct endpoint
        """
        if not url:
            return url

        url = url.strip()
        parsed = urlparse(url)

        if parsed.path and parsed.path != '/':
            self.print_stderr(
                f"Warning: URL '{url}' contains path '{parsed.path}'. "
                f"Using base URL only: '{parsed.scheme}://{parsed.netloc}'"
            )
            base_url = urlunparse((parsed.scheme, parsed.netloc, '', '', '', ''))
        else:
            base_url = url.rstrip('/')

        return f'{base_url}{SCAN_ENDPOINT}'

    def __init__(  # noqa: PLR0912, PLR0913, PLR0915
        self,
        scan_format: str = None,
        flags: str = None,
        url: str = None,
        api_key: str = None,
        debug: bool = False,
        trace: bool = False,
        quiet: bool = False,
        timeout: int = DEFAULT_TIMEOUT,
        ver_details: str = None,
        ignore_cert_errors: bool = False,
        proxy: str = None,
        ca_cert: str = None,
        pac: PACFile = None,
        retry: int = 5,
        req_headers: dict = None,
    ):
        """
        Initialise the SCANOSS API
        :param scan_format: Scan format (default plain)
        :param flags: Scanning flags (default None)
        :param url: API base URL (default https://api.osskb.org). The /scan/direct endpoint is automatically appended.
        :param api_key: API Key (default None)
        :param debug: Enable debug (default False)
        :param trace: Enable trace (default False)
        :param quiet: Enable quiet mode (default False)

        To set a custom certificate use:
            REQUESTS_CA_BUNDLE=/path/to/cert.pem
        To enable a Proxy use:
            HTTP_PROXY='http://<ip>:<port>'
            HTTPS_PROXY='http://<ip>:<port>'
        """
        super().__init__(debug, trace, quiet)
        self.sbom = None
        self.scan_format = scan_format if scan_format else 'plain'
        self.flags = flags
        self.timeout = timeout if timeout > MIN_TIMEOUT else DEFAULT_TIMEOUT
        self.retry_limit = retry if retry >= 0 else 5
        self.ignore_cert_errors = ignore_cert_errors
        self.req_headers = req_headers if req_headers else {}
        self.headers = {}
        base_url = url if url else SCANOSS_SCAN_URL
        self.api_key = api_key if api_key else SCANOSS_API_KEY
        if self.api_key and not url and not os.environ.get('SCANOSS_SCAN_URL'):
            base_url = DEFAULT_URL2
        self.url = self.normalize_api_url(base_url)
        if ver_details:
            self.headers['x-scanoss-client'] = ver_details
        if self.api_key:
            self.headers['X-Session'] = self.api_key
            self.headers['x-api-key'] = self.api_key
        user_agent = f'scanoss-py/{__version__}'
        self.headers['User-Agent'] = user_agent
        self.headers['user-agent'] = user_agent
        self.load_generic_headers(url)

        if self.trace:
            logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
            http_client.HTTPConnection.debuglevel = 1
        if pac and not proxy:
            self.print_debug('Setting up PAC session...')
            self.session = PACSession(pac=pac)
        else:
            self.session = requests.sessions.Session()
        self.verify = None
        if self.ignore_cert_errors:
            self.print_debug('Ignoring cert errors...')
            urllib3.disable_warnings(InsecureRequestWarning)
            self.verify = False
            self.session.verify = False
        elif ca_cert:
            self.verify = ca_cert
            self.session.verify = ca_cert
        self.proxies = {'https': proxy, 'http': proxy} if proxy else None
        if self.proxies:
            self.session.proxies = self.proxies

    def scan(self, wfp: str, context: str = None, scan_id: int = None):  # noqa: PLR0912, PLR0915
        """
        Scan the specified WFP and return the JSON object
        :param wfp: WFP to scan
        :param context: Context to help with identification
        :param scan_id: ID of the scan being run (usually thread id)
        :return: JSON result object
        """
        request_id = str(uuid.uuid4())
        form_data = {}
        if self.sbom:
            form_data['type'] = self.sbom.get('scan_type')
            form_data['assets'] = self.sbom.get('assets')
        if self.scan_format:
            form_data['format'] = self.scan_format
        if self.flags:
            form_data['flags'] = self.flags
        if context:
            form_data['context'] = context

        scan_files = {'file': ('%s.wfp' % request_id, wfp)}
        headers = self.headers
        headers['x-request-id'] = request_id  # send a unique request id for each post
        r = None
        retry = 0  # Add some retry logic to cater for timeouts, etc.
        while retry <= self.retry_limit:
            retry += 1
            try:
                r = None
                r = self.session.post(
                    self.url, files=scan_files, data=form_data, headers=self.headers, timeout=self.timeout
                )
            except (requests.exceptions.SSLError, requests.exceptions.ProxyError) as e:
                self.print_stderr(f'ERROR: Exception ({e.__class__.__name__}) POSTing data - {e}.')
                raise Exception(f'ERROR: The SCANOSS API request failed for {self.url}') from e
            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
                if retry > self.retry_limit:  # Timed out retry_limit or more times, fail
                    self.print_stderr(f'ERROR: {e.__class__.__name__} POSTing data ({request_id}) - {e}: {scan_files}')
                    raise Exception(
                        f'ERROR: The SCANOSS API request timed out ({e.__class__.__name__}) for {self.url}'
                    ) from e
                else:
                    self.print_stderr(f'Warning: {e.__class__.__name__} communicating with {self.url}. Retrying...')
                    time.sleep(5)
            except Exception as e:
                self.print_stderr(
                    f'ERROR: Exception ({e.__class__.__name__}) POSTing data ({request_id}) - {e}: {scan_files}'
                )
                raise Exception(f'ERROR: The SCANOSS API request failed for {self.url}') from e
            else:
                if r is None:
                    if retry > self.retry_limit:  # No response retry_limit or more times, fail
                        self.save_bad_req_wfp(scan_files, request_id, scan_id)
                        raise Exception(
                            f'ERROR: The SCANOSS API request ({request_id}) response object is empty for {self.url}'
                        )
                    else:
                        self.print_stderr(f'Warning: No response received from {self.url}. Retrying...')
                        time.sleep(5)
                elif r.status_code == requests.codes.service_unavailable:  # Service limits most likely reached
                    self.print_stderr(
                        f'ERROR: SCANOSS API rejected the scan request ({request_id}) due to '
                        f'service limits being exceeded'
                    )
                    self.print_stderr(f'ERROR: Details: {r.text.strip()}')
                    raise Exception(
                        f'ERROR: {r.status_code} - The SCANOSS API request ({request_id}) rejected '
                        f'for {self.url} due to service limits being exceeded.'
                    )
                elif r.status_code >= requests.codes.bad_request:
                    if retry > self.retry_limit:  # No response retry_limit or more times, fail
                        self.save_bad_req_wfp(scan_files, request_id, scan_id)
                        raise Exception(
                            f'ERROR: The SCANOSS API returned the following error: HTTP {r.status_code}, '
                            f'{r.text.strip()}'
                        )
                    else:
                        self.save_bad_req_wfp(scan_files, request_id, scan_id)
                        self.print_stderr(
                            f'Warning: Error response code {r.status_code} ({r.text.strip()}) from '
                            f'{self.url}. Retrying...'
                        )
                        time.sleep(5)
                else:
                    break  # Valid response, break out of the retry loop
        # End of while loop
        if r is None:
            self.save_bad_req_wfp(scan_files, request_id, scan_id)
            raise Exception(f'ERROR: The SCANOSS API request response object is empty for {self.url}')
        try:
            if 'xml' in self.scan_format:  # TODO remove XML parsing option?
                return r.text
            json_resp = r.json()
            return json_resp
        except (JSONDecodeError, Exception) as e:
            self.print_stderr(
                f'ERROR: The SCANOSS API returned an invalid JSON ({e.__class__.__name__} - {request_id}): {e}'
            )
            bad_json_file = f'bad_json-{scan_id}-{request_id}.txt' if scan_id else f'bad_json-{request_id}.txt'
            self.print_stderr(f'Ignoring result. Please look in "{bad_json_file}" for more details.')
            try:
                with open(bad_json_file, 'w') as f:
                    f.write(f'---Request ID Begin---\n{request_id}\n---Request ID End---\n')
                    f.write(f'---WFP Begin---\n{scan_files}\n---WFP End---\n---Bad JSON Begin---\n')
                    f.write(r.text)
                    f.write('---Bad JSON End---\n')
            except Exception as ee:
                self.print_stderr(
                    f'Warning: Issue writing bad json file - {bad_json_file} ({ee.__class__.__name__}): {ee}'
                )
            return None

    def save_bad_req_wfp(self, scan_files, request_id, scan_id):
        """
        Save the given WFP to a bad_request file
        :param scan_files: WFP
        :param request_id: request ID
        :param scan_id: scan thread id (optional)
        """
        bad_req_file = f'bad_request-{scan_id}-{request_id}.txt' if scan_id else f'bad_request-{request_id}.txt'
        try:
            self.print_stderr(
                f'No response object returned from API. Please look in "{bad_req_file}" for the offending WFP.'
            )
            with open(bad_req_file, 'w') as f:
                f.write(f'---Request ID Begin---\n{request_id}\n---Request ID End---\n')
                f.write(f'---WFP Begin---\n{scan_files}\n---WFP End---\n')
        except Exception as ee:
            self.print_stderr(
                f'Warning: Issue writing bad request file - {bad_req_file} ({ee.__class__.__name__}): {ee}'
            )

    def set_sbom(self, sbom):
        self.sbom = sbom
        return self

    def load_generic_headers(self, url):
        """
        Adds custom headers from req_headers to the headers collection.

        If x-api-key is present and no URL is configured (directly or via
        environment), sets URL to the premium endpoint (DEFAULT_URL2).
        """
        if self.req_headers:  # Load generic headers
            for key, value in self.req_headers.items():
                if key == 'x-api-key':  # Set premium URL if x-api-key header is set
                    if not url and not os.environ.get('SCANOSS_SCAN_URL'):
                        # API key specific and no alternative URL, so use the default premium
                        self.url = self.normalize_api_url(DEFAULT_URL2)
                    self.api_key = value
                self.headers[key] = value


#
# End of ScanossApi Class
#
