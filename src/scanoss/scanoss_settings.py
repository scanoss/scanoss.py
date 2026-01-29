"""
SPDX-License-Identifier: MIT

  Copyright (c) 2024, SCANOSS

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the 'Software'), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.
"""

import json
from pathlib import Path
from typing import List, Optional, TypedDict

import importlib_resources
from jsonschema import validate

from .scanossbase import ScanossBase
from .utils.file import (
    JSON_ERROR_FILE_EMPTY,
    JSON_ERROR_FILE_NOT_FOUND,
    validate_json_file,
)

DEFAULT_SCANOSS_JSON_FILE = Path('scanoss.json')


class BomEntry(TypedDict, total=False):
    purl: str
    path: str
    replace_with: str
    comment: str
    license: str


def matches_path(entry_path: str, result_path: str) -> bool:
    """
    Check if a BOM entry path matches a result path.
    Folder paths (ending with '/') use prefix matching; file paths use exact matching.

    Args:
        entry_path: Path from the BOM entry
        result_path: Path from the scan result

    Returns:
        True if the entry path matches the result path
    """
    if not entry_path:
        return True
    if entry_path.endswith('/'):
        return result_path.startswith(entry_path)
    return entry_path == result_path


def entry_priority(entry: BomEntry) -> int:
    """
    Calculate the priority score for a BOM entry.
    Higher score means higher priority (more specific).

    Score 4: both path and purl (most specific)
    Score 2: purl only
    Score 1: path only (remove only, no purl)

    Args:
        entry: BOM entry to evaluate

    Returns:
        Priority score
    """
    has_path = bool(entry.get('path'))
    has_purl = bool(entry.get('purl'))
    if has_path and has_purl:
        return 4
    if has_purl:
        return 2
    if has_path:
        return 1
    return 0


def find_best_match(result_path: str, result_purls: List[str], entries: List[BomEntry]) -> Optional[BomEntry]:
    """
    Find the highest-priority BOM entry that matches a result.
    When scores are equal, the longer path wins (more specific).

    Args:
        result_path: Path from the scan result
        result_purls: List of purls from the scan result
        entries: List of BOM entries to check

    Returns:
        The best matching BOM entry, or None if no match
    """
    best_entry = None
    best_score = -1
    best_path_len = -1

    for entry in entries:
        entry_path = entry.get('path', '')
        entry_purl = entry.get('purl', '')

        if not entry_path and not entry_purl:
            continue
        if entry_path and not matches_path(entry_path, result_path):
            continue
        if entry_purl and (not result_purls or entry_purl not in result_purls):
            continue

        score = entry_priority(entry)
        path_len = len(entry_path)
        if score > best_score or (score == best_score and path_len > best_path_len):
            best_entry = entry
            best_score = score
            best_path_len = path_len

    return best_entry


class SizeFilter(TypedDict, total=False):
    patterns: List[str]
    min: int
    max: int


class ScanossSettingsError(Exception):
    pass


def _load_settings_schema() -> dict:
    """
    Load the SCANOSS settings schema from a JSON file.

    Returns:
        dict: The parsed JSON content of the SCANOSS settings schema.

    Raises:
        ScanossSettingsError: If there is any issue in locating, reading, or parsing the JSON file
    """
    try:
        schema_path = importlib_resources.files(__name__) / 'data' / 'scanoss-settings-schema.json'
        with importlib_resources.as_file(schema_path) as f:
            with open(f, 'r', encoding='utf-8') as file:
                return json.load(file)
    except Exception as e:
        raise ScanossSettingsError(f'ERROR: Problem parsing Scanoss Settings Schema JSON file: {e}') from e


class ScanossSettings(ScanossBase):
    """
    Handles the loading and parsing of the SCANOSS settings file
    """

    def __init__(
        self,
        debug: bool = False,
        trace: bool = False,
        quiet: bool = False,
        filepath: 'str | None' = None,
    ):
        """
        Args:
            debug (bool, optional): Debug. Defaults to False.
            trace (bool, optional): Trace. Defaults to False.
            quiet (bool, optional): Quiet. Defaults to False.
            filepath (str, optional): Path to settings file. Defaults to None.
        """
        super().__init__(debug, trace, quiet)
        self.data = {}
        self.settings_file_type = None
        self.scan_type = None
        self.schema = _load_settings_schema()
        if filepath:
            self.load_json_file(filepath)

    def load_json_file(self, filepath: Optional[str] = None, scan_root: Optional[str] = None) -> 'ScanossSettings':
        """
        Load the scan settings file. If no filepath is provided, scanoss.json will be used as default.

        Args:
            filepath (str): Path to the SCANOSS settings file
        """

        if not filepath:
            filepath = DEFAULT_SCANOSS_JSON_FILE

        filepath = Path(scan_root) / filepath if scan_root else Path(filepath)

        json_file = filepath.resolve()

        if filepath == DEFAULT_SCANOSS_JSON_FILE and not json_file.exists():
            self.print_debug(f'Default settings file "{filepath}" not found. Skipping...')
            return self
        self.print_msg(f'Loading settings file {filepath}...')

        result = validate_json_file(json_file)
        if not result.is_valid:
            if result.error_code in (JSON_ERROR_FILE_NOT_FOUND, JSON_ERROR_FILE_EMPTY):
                self.print_msg(
                    f'WARNING: The supplied settings file "{filepath}" was not found or is empty. Skipping...'
                )
                return self
            else:
                raise ScanossSettingsError(f'Problem with settings file. {result.error}')
        try:
            validate(result.data, self.schema)
        except Exception as e:
            raise ScanossSettingsError(f'Invalid settings file. {e}') from e
        self.data = result.data
        self.print_debug(f'Loading scan settings from: {filepath}')
        return self

    def set_file_type(self, file_type: str):
        """
        Set the file type in order to support both legacy SBOM.json and new scanoss.json files
        Args:
            file_type (str): 'legacy' or 'new'

        Raises:
            Exception: Invalid scan settings file, missing "components" or "bom"
        """
        self.settings_file_type = file_type
        if not self._is_valid_sbom_file:
            raise Exception('Invalid scan settings file, missing "components" or "bom")')
        return self

    def set_scan_type(self, scan_type: str):
        """
        Set the scan type to support legacy SBOM.json files
        Args:
            scan_type (str): 'identify' or 'exclude'
        """
        self.scan_type = scan_type
        return self

    def _is_valid_sbom_file(self):
        """
        Check if the scan settings file is valid
        Returns:
            bool: True if the file is valid, False otherwise
        """
        if not self.data.get('components') or not self.data.get('bom'):
            return False
        return True

    def _get_bom(self):
        """
        Get the Bill of Materials from the settings file
        Returns:
            dict: If using scanoss.json
            list: If using SBOM.json
        """
        if self.settings_file_type == 'legacy':
            if isinstance(self.data, list):
                return self.data
            elif isinstance(self.data, dict) and self.data.get('components'):
                return self.data.get('components')
            else:
                return []
        return self.data.get('bom', {})

    def get_bom_include(self) -> List[BomEntry]:
        """
        Get the list of components to include in the scan
        Returns:
            list: List of components to include in the scan
        """
        if self.settings_file_type == 'legacy':
            return self._get_bom()
        return self._get_bom().get('include', [])


    def get_bom_exclude(self) -> List[BomEntry]:
        """
        Get the list of components to exclude from the scan
        Returns:
            list: List of components to exclude from the scan
        """
        if self.settings_file_type == 'legacy':
            return self._get_bom()
        return self._get_bom().get('exclude', [])

    def get_bom_remove(self) -> List[BomEntry]:
        """
        Get the list of components to remove from the scan
        Returns:
            list: List of components to remove from the scan
        """
        if self.settings_file_type == 'legacy':
            return self._get_bom()
        return self._get_bom().get('remove', [])

    def get_bom_replace(self) -> List[BomEntry]:
        """
        Get the list of components to replace in the scan
        Returns:
            list: List of components to replace in the scan
        """
        if self.settings_file_type == 'legacy':
            return []
        return self._get_bom().get('replace', [])

    def get_sbom(self):
        """
        Get the SBOM to be sent to the SCANOSS API
        Returns:
            dict: SBOM request payload
        """
        if not self.data:
            return None
        return {
            'assets': json.dumps(self._get_sbom_assets()),
            'scan_type': self.scan_type,
        }

    def _get_sbom_assets(self):
        """
        Get the SBOM assets
        Returns:
            List: List of SBOM assets
        """

        if self.settings_file_type == 'new':
            if len(self.get_bom_include()):
                self.scan_type = 'identify'
                include_bom_entries = self._remove_duplicates(self.normalize_bom_entries(self.get_bom_include()))
                return {"components": include_bom_entries}
            elif len(self.get_bom_exclude()):
                self.scan_type = 'blacklist'
                exclude_bom_entries = self._remove_duplicates(self.normalize_bom_entries(self.get_bom_exclude()))
                return {"components": exclude_bom_entries}

        if self.settings_file_type == 'legacy' and self.scan_type == 'identify':            # sbom-identify.json
            include_bom_entries = self._remove_duplicates(self.normalize_bom_entries(self.get_bom_include()))
            replace_bom_entries = self._remove_duplicates(self.normalize_bom_entries(self.get_bom_replace()))
            self.print_debug(
                f"Scan type set to 'identify'. Adding {len(include_bom_entries) + len(replace_bom_entries)} components as context to the scan. \n"  # noqa: E501
                f'From Include list: {[entry["purl"] for entry in include_bom_entries]} \n'
                f'From Replace list: {[entry["purl"] for entry in replace_bom_entries]} \n'
            )
            return include_bom_entries + replace_bom_entries

        if self.settings_file_type == 'legacy' and self.scan_type == 'blacklist':            # sbom-identify.json
            exclude_bom_entries = self._remove_duplicates(self.normalize_bom_entries(self.get_bom_exclude()))
            self.print_debug(
                f"Scan type set to 'blacklist'. Adding {len(exclude_bom_entries)} components as context to the scan. \n"  # noqa: E501
                f'From Exclude list: {[entry["purl"] for entry in exclude_bom_entries]} \n')
            return exclude_bom_entries

        return self.normalize_bom_entries(self.get_bom_remove())

    def has_path_scoped_bom_entries(self) -> bool:
        """
        Check if any include or exclude BOM entries have path-scoped rules.
        When path-scoped entries exist, the SBOM context must be resolved per-batch
        instead of sent globally with every request.

        Returns:
            True if any include/exclude entry has a path field
        """
        for entry in self.get_bom_include() + self.get_bom_exclude():
            if entry.get('path'):
                return True
        return False

    def get_sbom_for_batch(self, batch_file_paths: List[str]) -> Optional[dict]:
        """
        Get the SBOM context filtered for a specific batch of files.
        Only includes purls from entries whose path matches files in the batch.

        Purl-only entries (no path) are always included.
        File entries are included only if the exact file is in the batch.
        Folder entries are included only if any file in the batch is under that folder.

        Args:
            batch_file_paths: List of file paths in the current WFP batch

        Returns:
            SBOM payload dict with 'assets' and 'scan_type', or None
        """
        if not self.data:
            return None

        include_entries = self.get_bom_include()
        exclude_entries = self.get_bom_exclude()

        if not include_entries and not exclude_entries:
            return None

        bom_entries = include_entries or exclude_entries
        scan_type = 'identify' if include_entries else 'blacklist'

        filtered_purls = set()
        for entry in bom_entries:
            entry_path = entry.get('path', '')
            entry_purl = entry.get('purl', '')
            if not entry_purl:
                continue
            if not entry_path:
                filtered_purls.add(entry_purl)
                continue
            for file_path in batch_file_paths:
                if matches_path(entry_path, file_path):
                    filtered_purls.add(entry_purl)
                    break

        if not filtered_purls:
            return None

        components = [{'purl': p} for p in sorted(filtered_purls)]
        return {
            'assets': json.dumps({'components': components}),
            'scan_type': scan_type,
        }

    @staticmethod
    def normalize_bom_entries(bom_entries) -> List[BomEntry]:
        """
        Normalize the BOM entries by extracting only the purl field.

        Args:
            bom_entries (List[Dict]): List of BOM entries
        Returns:
            List: Normalized BOM entries
        """
        normalized_bom_entries = []
        for entry in bom_entries:
            normalized_bom_entries.append(
                {
                    'purl': entry.get('purl', ''),
                }
            )
        return normalized_bom_entries

    @staticmethod
    def _remove_duplicates(bom_entries: List[BomEntry]) -> List[BomEntry]:
        """
        Remove duplicate BOM entries
        Args:
            bom_entries (List[Dict]): List of BOM entries
        Returns:
            List: List of unique BOM entries
        """
        already_added = set()
        unique_entries = []
        for entry in bom_entries:
            entry_tuple = tuple(entry.items())
            if entry_tuple not in already_added:
                already_added.add(entry_tuple)
                unique_entries.append(entry)
        return unique_entries

    def is_legacy(self):
        """Check if the settings file is legacy"""
        return self.settings_file_type == 'legacy'

    def get_skip_patterns(self, operation_type: str) -> List[str]:
        """
        Get the list of patterns to skip based on the operation type
        Args:
            operation_type (str): Operation type
        Returns:
            List: List of patterns to skip
        """
        return self.data.get('settings', {}).get('skip', {}).get('patterns', {}).get(operation_type, [])

    def get_skip_sizes(self, operation_type: str) -> List[SizeFilter]:
        """
        Get the min and max sizes to skip based on the operation type
        Args:
            operation_type (str): Operation type
        Returns:
            List: Min and max sizes to skip
        """
        return self.data.get('settings', {}).get('skip', {}).get('sizes', {}).get(operation_type, [])

    def get_file_snippet_settings(self) -> dict:
        """
        Get the file_snippet settings section
        Returns:
            dict: File snippet settings
        """
        return self.data.get('settings', {}).get('file_snippet', {})

    def get_min_snippet_hits(self) -> Optional[int]:
        """
        Get the minimum snippet hits required
        Returns:
            int or None: Minimum snippet hits, or None if not set
        """
        return self.get_file_snippet_settings().get('min_snippet_hits')

    def get_min_snippet_lines(self) -> Optional[int]:
        """
        Get the minimum snippet lines required
        Returns:
            int or None: Minimum snippet lines, or None if not set
        """
        return self.get_file_snippet_settings().get('min_snippet_lines')

    def get_ranking_enabled(self) -> Optional[bool]:
        """
        Get whether ranking is enabled
        Returns:
            bool or None: True if enabled, False if disabled, None if not set
        """
        return self.get_file_snippet_settings().get('ranking_enabled')

    def get_ranking_threshold(self) -> Optional[int]:
        """
        Get the ranking threshold value
        Returns:
            int or None: Ranking threshold, or None if not set
        """
        return self.get_file_snippet_settings().get('ranking_threshold')

    def get_honour_file_exts(self) -> Optional[bool]:
        """
        Get whether to honour file extensions
        Returns:
            bool or None: True to honour, False to ignore, None if not set
        """
        return self.get_file_snippet_settings().get('honour_file_exts')

    def get_skip_headers_limit(self) -> int:
        """
        Get the skip headers limit value
        Returns:
            int: Skip headers limit, or 0 if not set
        """
        return self.get_file_snippet_settings().get('skip_headers_limit', 0)

    def get_skip_headers(self) -> bool:
        """
        Get whether to skip headers
        Returns:
            bool: True to skip headers, False otherwise (default)
        """
        return self.get_file_snippet_settings().get('skip_headers', False)

    def get_proxy(self) -> Optional[dict]:
        """
        Get the root-level proxy configuration
        Returns:
            dict or None: Proxy configuration with 'host' key, or None if not set
        """
        return self.data.get('settings', {}).get('proxy')

    def get_http_config(self) -> Optional[dict]:
        """
        Get the root-level http_config configuration
        Returns:
            dict or None: HTTP config with 'base_uri' and 'ignore_cert_errors' keys, or None if not set
        """
        return self.data.get('settings', {}).get('http_config')

    def get_file_snippet_proxy(self) -> Optional[dict]:
        """
        Get the file_snippet-level proxy configuration (takes priority over root)
        Returns:
            dict or None: Proxy configuration with 'host' key, or None if not set
        """
        return self.get_file_snippet_settings().get('proxy')

    def get_file_snippet_http_config(self) -> Optional[dict]:
        """
        Get the file_snippet-level http_config configuration (takes priority over root)
        Returns:
            dict or None: HTTP config with 'base_uri' and 'ignore_cert_errors' keys, or None if not set
        """
        return self.get_file_snippet_settings().get('http_config')
