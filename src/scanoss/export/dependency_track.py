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

import requests

from ..cyclonedx import CycloneDx
from ..scanossbase import ScanossBase
from ..services.dependency_track_service import DependencyTrackService
from ..utils.file import validate_json_file


def _build_payload(encoded_sbom: str, project_id, project_name, project_version) -> dict:
    """
    Build the API payload

    Args:
        encoded_sbom: Base64 encoded SBOM

    Returns:
        API payload dictionary
    """
    if project_id:
        return {'project': project_id, 'bom': encoded_sbom}
    else:
        return {
            'projectName': project_name,
            'projectVersion': project_version,
            'autoCreate': True,
            'bom': encoded_sbom,
        }


class DependencyTrackExporter(ScanossBase):
    """
    Class for exporting SBOM files to Dependency Track
    """
    def __init__( # noqa: PLR0913
        self,
        url: str = None,
        apikey: str = None,
        output: str = None,
        debug: bool = False,
        trace: bool = False,
        quiet: bool = False
    ):
        """
        Initialize DependencyTrackExporter

        Args:
            url: Dependency Track URL
            apikey: Dependency Track API Key
            output: File to store output response data (optional)
            debug: Enable debug output
            trace: Enable trace output
            quiet: Enable quiet mode
        """
        super().__init__(debug=debug, trace=trace, quiet=quiet)
        self.url = url.rstrip('/')
        self.apikey = apikey
        self.output = output
        self.dt_service = DependencyTrackService(self.apikey, self.url, debug=debug, trace=trace, quiet=quiet)

    def _read_and_validate_sbom(self, input_file: str) -> dict:
        """
        Read and validate the SBOM file

        Args:
            input_file: Path to the SBOM file

        Returns:
            Parsed SBOM content as dictionary

        Raises:
            ValueError: If the file doesn't exist or is invalid or not a valid CycloneDX SBOM
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
        if not sbom_content:
            self.print_stderr('Warning: Empty SBOM content provided')
            return ''
        # Check if SBOM has no components (empty scan results)
        components = sbom_content.get('components', [])
        if len(components) == 0:
            self.print_msg('Notice: SBOM contains no components (empty scan results)')
        json_str = json.dumps(sbom_content, separators=(',', ':'))
        encoded = base64.b64encode(json_str.encode('utf-8')).decode('utf-8')
        return encoded

    def upload_sbom_file(self, input_file, project_id, project_name, project_version, output_file):
        """
        Uploads an SBOM file to the specified project with an
        optional output file and processes the file content for validation.

        Args:
            input_file (str): The path to the SBOM file to be read and uploaded.
            project_id (str): The unique identifier of the project to which the SBOM is being uploaded.
            project_name (str): The name of the project to which the SBOM is being uploaded.
            project_version (str): The version of the project to which the SBOM is being uploaded.
            output_file (str): The path to save output related to the SBOM upload process.

        Returns:
            bool: Returns True if the SBOM file was uploaded successfully, False otherwise.

        Raises:
            ValueError: Raised if there are validation issues with the SBOM content.
        """
        try:
            if not self.quiet:
                self.print_stderr(f'Reading SBOM file: {input_file}')
            sbom_content = self._read_and_validate_sbom(input_file)
            return self.upload_sbom_contents(sbom_content, project_id, project_name, project_version, output_file)
        except ValueError as e:
            self.print_stderr(f'Validation error: {e}')
        return False

    def upload_sbom_contents(self, sbom_content: dict, project_id, project_name, project_version, output_file) -> bool:
        """
        Uploads an SBOM to a Dependency Track server.

        Parameters:
            sbom_content (dict): The SBOM content in dictionary format to be uploaded.
            project_id: The unique identifier for the project.
            project_name: The name of the project in Dependency Track.
            project_version: The version of the project in Dependency Track.
            output_file: The path to the file where the token and UUID data
                should be written. If not provided, the data will be written to
                standard output.

        Returns:
            bool: True if the upload is successful; False otherwise.

        Raises:
            ValueError: If the SBOM encoding process fails.
            requests.exceptions.RequestException: If an error occurs during the HTTP request.
            Exception: For any other unexpected error.
        """
        if not project_id and not (project_name and project_version):
            self.print_stderr('Error: Missing project id or name and version.')
            return False
        output = self.output
        if output_file:
            output = output_file
        try:
            self.print_debug('Encoding SBOM to base64')
            payload = _build_payload(self._encode_sbom(sbom_content), project_id, project_name, project_version)
            url = f'{self.url}/api/v1/bom'
            headers = {'Content-Type': 'application/json', 'X-Api-Key': self.apikey}
            self.print_trace(f'URL: {url}, Headers: {headers}, Payload keys: {list(payload.keys())}')
            self.print_msg('Uploading SBOM to Dependency Track...')
            response = requests.put(url, json=payload, headers=headers)
            response.raise_for_status()
            # Treat any 2xx status as success
            if (requests.codes.ok <= response.status_code < requests.codes.multiple_choices and
                    response.status_code != requests.codes.no_content):
                self.print_msg('SBOM uploaded successfully')
                try:
                    response_data = response.json()
                    token = ''
                    project_uuid = project_id
                    if 'token' in response_data:
                        token = response_data['token']
                    if project_name and project_version:
                      project_data = self.dt_service.get_project_by_name_version(project_name, project_version)
                      if project_data:
                         project_uuid = project_data.get("uuid", project_id)
                    token_json = json.dumps(
                        {"token": token, "project_uuid": project_uuid},
                        indent=2
                    )
                    self.print_to_file_or_stdout(token_json, output)
                except json.JSONDecodeError:
                    pass
                return True
            else:
                self.print_stderr(f'Upload failed with status code: {response.status_code}')
                self.print_stderr(f'Response: {response.text}')
        except ValueError as e:
            self.print_stderr(f'DT SBOM Upload Validation error: {e}')
        except requests.exceptions.RequestException as e:
            self.print_stderr(f'DT API Request error: {e}')
        except Exception as e:
            self.print_stderr(f'Unexpected error: {e}')
            if self.debug:
                traceback.print_exc()
        return False
