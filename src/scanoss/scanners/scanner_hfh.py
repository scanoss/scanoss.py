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

import json
import threading
import time
from typing import Dict, Optional

from progress.spinner import Spinner

from scanoss.constants import DEFAULT_HFH_RANK_THRESHOLD
from scanoss.cyclonedx import CycloneDx
from scanoss.file_filters import FileFilters
from scanoss.scanners.folder_hasher import FolderHasher
from scanoss.scanners.scanner_config import ScannerConfig
from scanoss.scanoss_settings import ScanossSettings
from scanoss.scanossbase import ScanossBase
from scanoss.scanossgrpc import ScanossGrpc
from scanoss.utils.abstract_presenter import AbstractPresenter


class ScannerHFH:
    """
    Folder Hashing Scanner.

    This scanner processes a directory, computes CRC64 hashes for the files,
    and calculates simhash values based on file names and content to detect folder-level similarities.
    """

    def __init__(
        self,
        scan_dir: str,
        config: ScannerConfig,
        client: Optional[ScanossGrpc] = None,
        scanoss_settings: Optional[ScanossSettings] = None,
        rank_threshold: int = DEFAULT_HFH_RANK_THRESHOLD,
    ):
        """
        Initialize the ScannerHFH.

        Args:
            scan_dir (str): The directory to be scanned.
            config (ScannerConfig): Configuration parameters for the scanner.
            client (ScanossGrpc): gRPC client for communicating with the scanning service.
            scanoss_settings (Optional[ScanossSettings]): Optional settings for Scanoss.
            rank_threshold (int): Get results with rank below this threshold (default: 5).
        """
        self.base = ScanossBase(
            debug=config.debug,
            trace=config.trace,
            quiet=config.quiet,
        )
        self.presenter = ScannerHFHPresenter(
            self,
            debug=config.debug,
            trace=config.trace,
            quiet=config.quiet,
        )
        self.file_filters = FileFilters(
            debug=config.debug,
            trace=config.trace,
            quiet=config.quiet,
            scanoss_settings=scanoss_settings,
        )
        self.folder_hasher = FolderHasher(
            scan_dir=scan_dir,
            config=config,
            scanoss_settings=scanoss_settings,
        )

        self.scan_dir = scan_dir
        self.client = client
        self.scan_results = None
        self.rank_threshold = rank_threshold

    def scan(self) -> Optional[Dict]:
        """
        Scan the provided directory using the folder hashing algorithm.

        Returns:
            Optional[Dict]: The folder hash response from the gRPC client, or None if an error occurs.
        """
        hfh_request = {
            'root': self.folder_hasher.hash_directory(self.scan_dir),
            'rank_threshold': self.rank_threshold,
        }

        spinner = Spinner('Scanning folder...')
        stop_spinner = False

        def spin():
            while not stop_spinner:
                spinner.next()
                time.sleep(0.1)

        spinner_thread = threading.Thread(target=spin)
        spinner_thread.start()

        try:
            response = self.client.folder_hash_scan(hfh_request)
            if response:
                self.scan_results = response
        finally:
            stop_spinner = True
            spinner_thread.join()
            spinner.finish()

        return self.scan_results

    def present(self, output_format: str = None, output_file: str = None):
        """Present the results in the selected format"""
        self.presenter.present(output_format=output_format, output_file=output_file)


class ScannerHFHPresenter(AbstractPresenter):
    """
    ScannerHFH presenter class
    Handles the presentation of the folder hashing scan results
    """

    def __init__(self, scanner: ScannerHFH, **kwargs):
        super().__init__(**kwargs)
        self.scanner = scanner

    def _format_json_output(self) -> str:
        """
        Format the scan output data into a JSON object

        Returns:
            str: The formatted JSON string
        """
        return json.dumps(self.scanner.scan_results, indent=2)

    def _format_plain_output(self) -> str:
        """
        Format the scan output data into a plain text string
        """
        return (
            json.dumps(self.scanner.scan_results, indent=2)
            if isinstance(self.scanner.scan_results, dict)
            else str(self.scanner.scan_results)
        )

    def _format_cyclonedx_output(self) -> str:
        if not self.scanner.scan_results:
            return ''
        try:
            if 'results' not in self.scanner.scan_results or not self.scanner.scan_results['results']:
                self.base.print_stderr('ERROR: No scan results found')
                return ''

            first_result = self.scanner.scan_results['results'][0]

            best_match_components = [c for c in first_result.get('components', []) if c.get('order') == 1]
            if not best_match_components:
                self.base.print_stderr('ERROR: No best match component found')
                return ''

            best_match_component = best_match_components[0]
            if not best_match_component.get('versions'):
                self.base.print_stderr('ERROR: No versions found for best match component')
                return ''

            best_match_version = best_match_component['versions'][0]
            purl = best_match_component['purl']

            get_dependencies_json_request = {
                'files': [
                    {
                        'file': f'{best_match_component["name"]}:{best_match_version["version"]}',
                        'purls': [{'purl': purl, 'requirement': best_match_version['version']}],
                    }
                ]
            }

            decorated_scan_results = self.scanner.client.get_dependencies(get_dependencies_json_request)

            cdx = CycloneDx(self.base.debug, self.output_file)
            scan_results = {}
            for f in decorated_scan_results['files']:
                scan_results[f['file']] = [f]
            if not cdx.produce_from_json(scan_results, self.output_file):
                error_msg = 'ERROR: Failed to produce CycloneDX output'
                self.base.print_stderr(error_msg)
                raise ValueError(error_msg)
        except Exception as e:
            self.base.print_stderr(f'ERROR: Failed to get license information: {e}')
            return None

    def _format_spdxlite_output(self) -> str:
        raise NotImplementedError('SPDXlite output is not implemented')

    def _format_csv_output(self) -> str:
        raise NotImplementedError('CSV output is not implemented')

    def _format_raw_output(self) -> str:
        raise NotImplementedError('Raw output is not implemented')
