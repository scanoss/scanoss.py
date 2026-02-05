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
from dataclasses import dataclass
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


@dataclass
class BomEntry:
    purl: Optional[str] = None
    path: Optional[str] = None
    comment: Optional[str] = None

    @classmethod
    def from_dict(cls, data: dict) -> 'BomEntry':
        return cls(
            purl=data.get('purl'),
            path=data.get('path'),
            comment=data.get('comment'),
        )

    def matches_path(self, result_path: str) -> bool:
        """
        Check if this entry's path matches a result path.
        Folder paths (ending with '/') use prefix matching; file paths use exact matching.

        Args:
            result_path: Path from the scan result

        Returns:
            True if this entry's path matches the result path
        """
        if not self.path:
            return True
        if self.path.endswith('/'):
            return result_path.startswith(self.path)
        return self.path == result_path

    @property
    def priority(self) -> int:
        """
        Priority score for this BOM entry. Higher score means higher priority (more specific).

        Score 4: both path and purl (most specific)
        Score 2: purl only
        Score 1: path only (remove only, no purl)

        Returns:
            Priority score
        """
        has_path = bool(self.path)
        has_purl = bool(self.purl)
        if has_path and has_purl:
            return 4
        if has_purl:
            return 2
        if has_path:
            return 1
        return 0


@dataclass
class ReplaceRule(BomEntry):
    replace_with: Optional[str] = None
    license: Optional[str] = None

    @classmethod
    def from_dict(cls, data: dict) -> 'ReplaceRule':
        return cls(
            purl=data.get('purl'),
            path=data.get('path'),
            comment=data.get('comment'),
            replace_with=data.get('replace_with'),
            license=data.get('license'),
        )


@dataclass(frozen=True)
class SbomContext:
    """SBOM context for a file or batch of files."""

    purls: tuple  # Use tuple for hashability (frozen dataclass)
    scan_type: Optional[str]

    def to_payload(self) -> Optional[dict]:
        """Convert to API payload dict."""
        if not self.purls or not self.scan_type:
            return None
        components = [{'purl': p} for p in self.purls]
        return {
            'assets': json.dumps({'components': components}),
            'scan_type': self.scan_type,
        }

    @classmethod
    def empty(cls) -> 'SbomContext':
        """Return empty context (no purls, no scan_type)."""
        return cls(purls=(), scan_type=None)

    @classmethod
    def union(cls, contexts: list) -> 'SbomContext':
        """Merge multiple contexts: union of purls, first non-None scan_type wins."""
        all_purls = []
        scan_type = None
        seen = set()
        for ctx in contexts:
            if scan_type is None and ctx.scan_type:
                scan_type = ctx.scan_type
            for p in ctx.purls:
                if p not in seen:
                    seen.add(p)
                    all_purls.append(p)
        return cls(purls=tuple(all_purls), scan_type=scan_type)


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
        entry_path = entry.path or ''
        entry_purl = entry.purl or ''

        if not entry_path and not entry_purl:
            continue
        if entry_path and not entry.matches_path(result_path):
            continue
        if entry_purl and (not result_purls or entry_purl not in result_purls):
            continue

        score = entry.priority
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
            raw = self._get_bom()
        else:
            raw = self._get_bom().get('include', [])
        return [BomEntry.from_dict(entry) for entry in raw]

    def get_bom_exclude(self) -> List[BomEntry]:
        """
        Get the list of components to exclude from the scan
        Returns:
            list: List of components to exclude from the scan
        """
        if self.settings_file_type == 'legacy':
            raw = self._get_bom()
        else:
            raw = self._get_bom().get('exclude', [])
        return [BomEntry.from_dict(entry) for entry in raw]

    def get_bom_remove(self) -> List[BomEntry]:
        """
        Get the list of components to remove from the scan
        Returns:
            list: List of components to remove from the scan
        """
        if self.settings_file_type == 'legacy':
            raw = self._get_bom()
        else:
            raw = self._get_bom().get('remove', [])
        return [BomEntry.from_dict(entry) for entry in raw]

    def get_bom_replace(self) -> List[ReplaceRule]:
        """
        Get the list of components to replace in the scan
        Returns:
            list: List of replace rules
        """
        if self.settings_file_type == 'legacy':
            return []
        raw = self._get_bom().get('replace', [])
        return [ReplaceRule.from_dict(entry) for entry in raw]

    def _get_purls_for_path(self, file_path: str, entries: List[BomEntry]) -> list:
        """
        Extract matching purls from entries for a given file path.

        Purl-only entries (no path) are always included.
        Path-scoped entries are included only if the file matches.
        When multiple rules match the same purl, the highest specificity is used.

        Args:
            file_path: File path to check
            entries: List of BomEntry to check against

        Returns:
            List of purl strings ordered by specificity (most specific first)
        """
        if not entries:
            return []

        purl_scores = {}
        for entry in entries:
            entry_purl = entry.purl or ''
            if not entry_purl:
                continue
            entry_path = entry.path or ''
            if not entry_path or entry.matches_path(file_path):
                # Score: priority (0-4) + path length (longer = more specific)
                score = entry.priority + len(entry_path)
                if entry_purl not in purl_scores or score > purl_scores[entry_purl]:
                    purl_scores[entry_purl] = score

        # Sort by score descending (most specific first)
        return sorted(purl_scores.keys(), key=lambda p: -purl_scores[p])

    def get_sbom_context(self, file_path: str) -> SbomContext:
        """
        Get SBOM context matching a file path.

        Logic:
        - Legacy files: use self.scan_type set during file load
        - New format: try include rules first, fall back to exclude rules

        Args:
            file_path: File path to check

        Returns:
            SbomContext with purls ordered by specificity
        """
        if not self.data:
            return SbomContext.empty()

        # Legacy files: use self.scan_type set during file load (--identify or --ignore flag)
        if self.is_legacy():
            raw = self._get_bom()
            entries = [BomEntry.from_dict(entry) for entry in raw]
            purls = self._get_purls_for_path(file_path, entries)
            if purls:
                return SbomContext(purls=tuple(purls), scan_type=self.scan_type)
            return SbomContext.empty()

        # New format: try include first, then exclude
        include_purls = self._get_purls_for_path(file_path, self.get_bom_include())
        if include_purls:
            return SbomContext(purls=tuple(include_purls), scan_type='identify')

        exclude_purls = self._get_purls_for_path(file_path, self.get_bom_exclude())
        if exclude_purls:
            return SbomContext(purls=tuple(exclude_purls), scan_type='blacklist')

        return SbomContext.empty()

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
