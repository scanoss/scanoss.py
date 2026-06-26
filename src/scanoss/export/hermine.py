"""
SPDX-License-Identifier: MIT

  Copyright (c) 2026, SCANOSS

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
from os import replace

import requests

from ..scanossbase import ScanossBase
from ..services.hermine_service import HermineService
from ..utils.file import validate_json_file


def _build_file_payload(input_file: str) -> dict:
    """
    Build the Hermine API payload.

    Args:
        input_file: Path to the SPDX SBOM file (JSON format)

    Returns:
        API payload dictionary
    """
    with open(input_file, 'rb') as f:
        file_content = f.read()
    return {
        "spdx_file": (input_file, file_content)
    }


class HermineExporter(ScanossBase):
    """
    Class for exporting SPDX SBOM files to Hermine.
    """

    def __init__(  # noqa: PLR0913
            self,
            url: str = None,
            api_key: str = None,
            output: str = None,
            debug: bool = False,
            trace: bool = False,
            quiet: bool = False
    ):
        """
        Initialize HermineExporter.

        Args:
            url: Hermine URL
            api_key: Hermine API key
            output: File to store output response data (optional)
            debug: Enable debug output
            trace: Enable trace output
            quiet: Enable quiet mode
        """
        super().__init__(debug=debug, trace=trace, quiet=quiet)
        self.url = url.rstrip('/') if url else None
        self.api_key = api_key
        self.output = output
        self.hm_service = HermineService(self.api_key, self.url, debug=debug, trace=trace, quiet=quiet)

    def _read_and_validate_sbom(self, input_file: str):
        """
        Read and validate the SBOM file.

        Args:
            input_file: Path to the SPDX SBOM file (JSON format)

        Returns:
            Parsed SBOM content as dictionary

        Raises:
            ValueError: If the file doesn't exist, is invalid JSON, or is not a valid SPDX SBOM
        """
        result = validate_json_file(input_file)
        if not result.is_valid:
            raise ValueError(f'Invalid JSON file: {result.error}')
        if 'spdxVersion' not in result.data:
            raise ValueError(f'Input file is not a valid SPDX SBOM: {input_file}')
        return None

    def upload_sbom_file(self, input_file, product_name, release_name, output_file) -> bool:
        """
        Upload an SPDX SBOM file to Hermine.

        Args:
            input_file: Path to the SPDX SBOM file to upload
            product_name: Product name in Hermine
            release_name: Product release in Hermine
            output_file: Path to save upload response data

        Returns:
            True if uploaded successfully, False otherwise
        """
        try:
            if not self.quiet:
                self.print_stderr(f'Reading SBOM file: {input_file}')
            self._read_and_validate_sbom(input_file)

            product_id, release_id = self.hm_service.get_ids(product_name, release_name)
            file_payload = _build_file_payload(input_file)
            data = {
                "release": release_id,
                "replace": "true"
            }
            return self.upload_sbom_contents(data, file_payload, output_file)
        except ValueError as e:
            self.print_stderr(f'Validation error: {e}')
        return False

    def upload_sbom_contents(self, data, file_payload, output_file) -> bool:
        """
        Upload an SPDX SBOM to Hermine.

        Args:
            data: API payload data
            file_payload: File payload
            output_file: Path to save the upload response data

        Returns:
            True if upload successful, False otherwise
        """
        output = self.output
        if output_file:
            output = output_file
        try:
            response = self.hm_service.get_hermine_data(f'{self.url}/api/upload_spdx/', data=data, files=file_payload)
            response.raise_for_status()

        except NotImplementedError:
            raise
        except ValueError as e:
            self.print_stderr(f'Hermine SBOM Upload Validation error: {e}')
        except Exception as e:
            self.print_stderr(f'Unexpected error: {e}')
            if self.debug:
                traceback.print_exc()
        self.print_msg('Upload complete.')
        return False
