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

    @staticmethod
    def normalize_bom_entries(bom_entries) -> List[BomEntry]:
        """
        Normalize the BOM entries
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
