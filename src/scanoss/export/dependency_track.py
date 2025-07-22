"""
SPDX-License-Identifier: MIT

  Copyright (c) 2025, SCANOSS

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

import base64
import json
import traceback
from dataclasses import dataclass
from typing import Optional

import requests

from scanoss.cyclonedx import CycloneDx

from ..scanossbase import ScanossBase
from ..utils.file import validate_json_file


@dataclass
class DependencyTrackExporterConfig:
    debug: bool = False
    trace: bool = False
    quiet: bool = False
    dt_url: str = None
    dt_apikey: str = None
    dt_projectid: Optional[str] = None
    dt_projectname: Optional[str] = None
    dt_projectversion: Optional[str] = None


def create_dependency_track_exporter_config_from_args(args) -> DependencyTrackExporterConfig:
    return DependencyTrackExporterConfig(
        debug=getattr(args, 'debug', False),
        trace=getattr(args, 'trace', False),
        quiet=getattr(args, 'quiet', False),
        dt_url=getattr(args, 'dt_url', None),
        dt_apikey=getattr(args, 'dt_apikey', None),
        dt_projectid=getattr(args, 'dt_projectid', None),
        dt_projectname=getattr(args, 'dt_projectname', None),
        dt_projectversion=getattr(args, 'dt_projectversion', None),
    )


class DependencyTrackExporter(ScanossBase):
    """
    Class for exporting SBOM files to Dependency Track
    """

    def __init__(
        self,
        config: DependencyTrackExporterConfig,
        debug: bool = False,
        trace: bool = False,
        quiet: bool = False,
    ):
        """
        Initialize DependencyTrackExporter

        Args:
            config: Configuration parameters for the dependency track exporter
            debug: Enable debug output
            trace: Enable trace output
            quiet: Enable quiet mode
        """
        super().__init__(debug=debug, trace=trace, quiet=quiet)

        self.dt_url = config.dt_url.rstrip('/')
        self.dt_apikey = config.dt_apikey
        self.dt_projectid = config.dt_projectid
        self.dt_projectname = config.dt_projectname
        self.dt_projectversion = config.dt_projectversion

        self._validate_config()

    def _validate_config(self):
        """
        Validate that the configuration is valid.
        """
        has_id = bool(self.dt_projectid)
        has_name_version = bool(self.dt_projectname and self.dt_projectversion)

        if not (has_id or has_name_version):
            raise ValueError('Either --dt-projectid OR (--dt-projectname and --dt-projectversion) must be provided')

        if has_id and has_name_version:
            self.print_debug('Both DT project ID and name/version provided. Using project ID.')

    def _read_and_validate_sbom(self, input_file: str) -> dict:
        """
        Read and validate the SBOM file

        Args:
            input_file: Path to the SBOM file

        Returns:
            Parsed SBOM content as dictionary

        Raises:
            ValueError: If file doesn't exist or is invalid or not a valid CycloneDX SBOM
        """
        result = validate_json_file(input_file)
        if not result.is_valid:
            raise ValueError(f'Invalid JSON file: {result.error}')

        cdx = CycloneDx(debug=self.debug)
        if not cdx.is_cyclonedx_json(json.dumps(result.data)):
            raise ValueError(f'Input file is not a valid CycloneDX SBOM: {input_file}')

        return result.data

    def _encode_sbom(self, sbom_content: dict) -> str:
        """
        Encode SBOM content to base64

        Args:
            sbom_content: SBOM dictionary

        Returns:
            Base64 encoded string
        """
        json_str = json.dumps(sbom_content, separators=(',', ':'))
        encoded = base64.b64encode(json_str.encode('utf-8')).decode('utf-8')
        return encoded

    def _build_payload(self, encoded_sbom: str) -> dict:
        """
        Build the API payload

        Args:
            encoded_sbom: Base64 encoded SBOM

        Returns:
            API payload dictionary
        """
        if self.dt_projectid:
            return {'project': self.dt_projectid, 'bom': encoded_sbom}
        else:
            return {
                'projectName': self.dt_projectname,
                'projectVersion': self.dt_projectversion,
                'autoCreate': True,
                'bom': encoded_sbom,
            }

    def upload_sbom(self, input_file: str) -> bool:
        """
        Upload SBOM file to Dependency Track

        Args:
            input_file: Path to the SBOM file

        Returns:
            True if successful, False otherwise
        """
        try:
            self.print_stderr(f'Reading SBOM file: {input_file}')
            sbom_content = self._read_and_validate_sbom(input_file)

            self.print_debug('Encoding SBOM to base64')
            encoded_sbom = self._encode_sbom(sbom_content)

            payload = self._build_payload(encoded_sbom)

            url = f'{self.dt_url}/api/v1/bom'
            headers = {'Content-Type': 'application/json', 'X-Api-Key': self.dt_apikey}

            if self.trace:
                self.print_trace(f'URL: {url}')
                self.print_trace(f'Headers: {headers}')
                self.print_trace(f'Payload keys: {list(payload.keys())}')

            self.print_msg('Uploading SBOM to Dependency Track...')
            response = requests.put(url, json=payload, headers=headers)

            if response.status_code in [200, 201]:
                self.print_stderr('SBOM uploaded successfully')

                try:
                    response_data = response.json()
                    if 'token' in response_data:
                        self.print_stderr(f'Upload token: {response_data["token"]}')
                except json.JSONDecodeError:
                    pass

                return True
            else:
                self.print_stderr(f'Upload failed with status code: {response.status_code}')
                self.print_stderr(f'Response: {response.text}')
                return False

        except ValueError as e:
            self.print_stderr(f'Validation error: {e}')
            return False
        except requests.exceptions.RequestException as e:
            self.print_stderr(f'Request error: {e}')
            return False
        except Exception as e:
            self.print_stderr(f'Unexpected error: {e}')
            if self.debug:
                traceback.print_exc()
            return False
