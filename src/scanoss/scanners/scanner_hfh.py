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

import hashlib
import json
import os
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from packageurl.contrib import purl2url
from progress.spinner import Spinner

from scanoss.constants import (
    DEFAULT_HFH_DEPTH,
    DEFAULT_HFH_MIN_ACCEPTED_SCORE,
    DEFAULT_HFH_RANK_THRESHOLD,
    DEFAULT_HFH_RECURSIVE_THRESHOLD,
)
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

    def __init__(  # noqa: PLR0913
        self,
        scan_dir: str,
        config: ScannerConfig,
        client: Optional[ScanossGrpc] = None,
        scanoss_settings: Optional[ScanossSettings] = None,
        rank_threshold: int = DEFAULT_HFH_RANK_THRESHOLD,
        depth: int = DEFAULT_HFH_DEPTH,
        recursive_threshold: float = DEFAULT_HFH_RECURSIVE_THRESHOLD,
        min_accepted_score: float = DEFAULT_HFH_MIN_ACCEPTED_SCORE,
        use_grpc: bool = False,
    ):
        """
        Initialize the ScannerHFH.

        Args:
            scan_dir (str): The directory to be scanned.
            config (ScannerConfig): Configuration parameters for the scanner.
            client (ScanossGrpc): gRPC client for communicating with the scanning service.
            scanoss_settings (Optional[ScanossSettings]): Optional settings for Scanoss.
            rank_threshold (int): Get results with rank below this threshold (default: 5).
            depth (int): How many levels to scan (default: 1).
            recursive_threshold (float): Minimum score threshold to consider a match (default: 0.25).
            min_accepted_score (float): Only show results with a score at or above this threshold (default: 0.15).
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
            depth=depth,
        )

        self.scan_dir = scan_dir
        self.client = client
        self.scan_results = None
        self.rank_threshold = rank_threshold
        self.recursive_threshold = recursive_threshold
        self.min_accepted_score = min_accepted_score
        self.use_grpc = use_grpc

    def _execute_grpc_scan(self, hfh_request: Dict) -> None:
        """
        Execute folder hash scan.

        Args:
            hfh_request: Request dictionary for the gRPC call
        """
        try:
            self.scan_results = self.client.folder_hash_scan(hfh_request, self.use_grpc)
        except Exception as e:
            self.base.print_stderr(f'Error during folder hash scan: {e}')
            self.scan_results = None

    def scan(self) -> Optional[Dict]:
        """
        Scan the provided directory using the folder hashing algorithm.

        Returns:
            Optional[Dict]: The folder hash response from the gRPC client, or None if an error occurs.
        """
        hfh_request = {
            'root': self.folder_hasher.hash_directory(path=self.scan_dir),
            'rank_threshold': self.rank_threshold,
            'recursive_threshold': self.recursive_threshold,
            'min_accepted_score': self.min_accepted_score,
        }

        spinner_ctx = Spinner('Scanning folder...')

        with spinner_ctx as spinner:
            grpc_thread = threading.Thread(target=self._execute_grpc_scan, args=(hfh_request,))
            grpc_thread.start()

            while grpc_thread.is_alive():
                spinner.next()
                time.sleep(0.1)

            grpc_thread.join()

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
        """
        Initialize the presenter.

        Args:
            scanner (ScannerHFH): The HFH scanner instance containing scan results and file filters.
            **kwargs: Additional arguments passed to AbstractPresenter (debug, trace, quiet, etc.).
        """
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

    def _format_cyclonedx_output(self) -> str:  # noqa: PLR0911
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

            get_vulnerabilities_json_request = {
                'components': [{'purl': purl, 'requirement': best_match_version['version']}],
            }

            decorated_scan_results = self.scanner.client.get_dependencies(get_dependencies_json_request)
            vulnerabilities = self.scanner.client.get_vulnerabilities_json(get_vulnerabilities_json_request)

            cdx = CycloneDx(self.base.debug)
            scan_results = {}
            for f in decorated_scan_results['files']:
                scan_results[f['file']] = [f]
            success, cdx_output = cdx.produce_from_json(scan_results)
            if not success:
                error_msg = 'ERROR: Failed to produce CycloneDX output'
                self.base.print_stderr(error_msg)
                return None

            if vulnerabilities:
                cdx_output = cdx.append_vulnerabilities(cdx_output, vulnerabilities, purl)

            return json.dumps(cdx_output, indent=2)
        except Exception as e:
            self.base.print_stderr(f'ERROR: Failed to get license information: {e}')
            return None

    def _format_spdxlite_output(self) -> str:
        raise NotImplementedError('SPDXlite output is not implemented')

    def _format_csv_output(self) -> str:
        raise NotImplementedError('CSV output is not implemented')

    def _format_raw_output(self) -> str:
        """
        Convert HFH scan results into snippet-scanner JSON format.

        Expands directory-level HFH results into per-file entries keyed by
        relative file path, matching the structure returned by the snippet scanner.
        For each file, computes the MD5 hash and constructs the file_url using
        the API base URL from the scanner config.

        Returns:
            str: A JSON string with the snippet-scanner format, or '{}' if no results.
        """
        if not self.scanner.scan_results or 'results' not in self.scanner.scan_results:
            return '{}'

        hfh_results = self.scanner.scan_results.get('results', [])
        if not hfh_results:
            return '{}'

        # Collect best-match component info per path_id
        path_components = self._extract_best_components(hfh_results)
        if not path_components:
            return '{}'

        # Get all filtered files once (relative paths to scan_dir)
        all_files = self.scanner.file_filters.get_filtered_files_from_folder(self.scanner.scan_dir)

        # Sort path_ids by depth (deepest first) so most-specific match wins.
        # Root path '.' is always last (-1), others sort by separator count then path length.
        # Example with path_ids: ['.', 'external', 'project-1.0', 'project-1.0/src/lib']
        #   Sorted result: ['project-1.0/src/lib', 'project-1.0', 'external', '.']
        #   - 'project-1.0/src/lib' (depth 2) claims its files first
        #   - 'project-1.0' (depth 0, len 11) claims remaining files under it
        #   - 'external' (depth 0, len 8) claims external/ files
        #   - '.' (root, always last) picks up everything else
        sorted_path_ids = sorted(
            path_components.keys(),
            key=lambda p: (-1, 0) if p == '.' else (p.count(os.sep), len(p)),
            reverse=True,
        )

        output = {}
        claimed_files = set()
        scan_dir = Path(self.scanner.scan_dir).resolve()

        for path_id in sorted_path_ids:
            component, best_version = path_components[path_id]
            for file_path in all_files:
                if file_path in claimed_files:
                    continue
                if not self._file_matches_path_id(file_path, path_id):
                    continue

                claimed_files.add(file_path)
                # Path.__truediv__ (/) joins paths using the correct OS separator
                file_hash = self._compute_file_md5(scan_dir / file_path)
                api_url = self.scanner.client.orig_url or ''
                entry = self._build_file_match_entry(component, best_version, file_path, file_hash, api_url)
                output[file_path] = [entry]

        return json.dumps(output, indent=2)

    @staticmethod
    def _extract_best_components(hfh_results: List[Dict]) -> Dict[str, Tuple[Dict, Dict]]:
        """
        Extract the best-match component and version for each path_id from HFH results.

        Filters for components with order == 1 (best match) and takes their first version.
        Results without a qualifying component or without versions are skipped.

        Args:
            hfh_results (List[Dict]): The 'results' list from the HFH API response.

        Returns:
            Dict[str, Tuple[Dict, Dict]]: A dict mapping path_id to (component, best_version).
        """
        path_components = {}
        for result in hfh_results:
            path_id = result.get('path_id', '.')
            components = result.get('components', [])
            best = [c for c in components if c.get('order') == 1]
            if not best:
                continue
            component = best[0]
            versions = component.get('versions', [])
            if not versions:
                continue
            path_components[path_id] = (component, versions[0])
        return path_components

    @staticmethod
    def _file_matches_path_id(file_path: str, path_id: str) -> bool:
        """
        Check if a file path belongs under a given path_id directory.

        Both file_path and path_id are relative to the scan root directory.
        A path_id of '.' matches all files (root directory).

        Args:
            file_path (str): Relative file path from the scan root.
            path_id (str): Relative directory path from the HFH result.

        Returns:
            bool: True if the file is under the given path_id directory.
        """
        if path_id == '.':
            return True
        # file_path and path_id are both relative to scan_dir
        return file_path == path_id or file_path.startswith(path_id + os.sep)

    def _compute_file_md5(self, file_path: Path) -> str:
        """
        Compute the MD5 hash of a file's contents.

        Uses the same approach as the snippet scanner (winnowing.py) to ensure
        consistent file_hash values across scan types.

        Args:
            file_path (Path): Absolute path to the file.

        Returns:
            str: The MD5 hex digest, or an empty string if the file cannot be read.
        """
        try:
            return hashlib.md5(file_path.read_bytes()).hexdigest()
        except (OSError, IOError) as e:
            self.base.print_stderr(f'Warning: Failed to compute MD5 for {file_path}: {e}')
            return ''

    @staticmethod
    def _build_file_match_entry(
        component: Dict, best_version: Dict, file_path: str, file_hash: str, base_url: str,
    ) -> Dict:
        """
        Build a snippet-scanner-compatible result entry from an HFH component.

        Maps HFH component fields to the standard scan result format. Fields not
        available from HFH (url_hash, release_date, licenses) are included as empty
        values since downstream validators require them.

        Args:
            component (Dict): The HFH component with purl, name, vendor fields.
            best_version (Dict): The top version entry with version and score fields.
            file_path (str): Relative file path from the scan root directory.
            file_hash (str): Pre-computed MD5 hash of the local file.
            base_url (str): API base URL used to construct the file_url field.

        Returns:
            Dict: A result entry compatible with the snippet-scanner JSON format.
        """
        purl = component.get('purl', '')
        version = best_version.get('version', '')

        url = purl2url.get_repo_url(purl) if purl else ''
        return {
            'id': 'file',
            'matched': '100%',
            'purl': [purl],
            'component': component.get('name', ''),
            'vendor': component.get('vendor', ''),
            'version': version,
            'latest': version,
            'url': url or '',
            'file': file_path,
            'file_hash': file_hash,
            'file_url': f'{base_url}/file_contents/{file_hash}',
            'source_hash': file_hash,
            'url_hash': '',
            'release_date': '',
            'licenses': [],
            'lines': 'all',
            'oss_lines': 'all',
            'status': 'pending',
        }
