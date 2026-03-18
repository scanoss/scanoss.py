"""
SPDX-License-Identifier: MIT

  Copyright (c) 2024, SCANOSS

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

from typing import List, Optional

from packageurl import PackageURL
from packageurl.contrib import purl2url

from .scanoss_settings import BomEntry, ReplaceRule, ScanossSettings, find_best_match
from .scanossbase import ScanossBase


def _get_match_type_message(result_path: str, bom_entry: BomEntry, action: str) -> str:
    """
    Compose message based on match type

    Args:
        result_path (str): Path of the scan result
        bom_entry (BomEntry): BOM entry to compare with
        action (str): Post processing action being performed

    Returns:
        str: The message to be printed
    """
    entry_path = bom_entry.path or ''
    if entry_path and bom_entry.purl:
        # Result keys are always file paths, so exact match means file-level rule;
        # otherwise the match came via folder prefix.
        match_kind = 'file' if entry_path == result_path else 'folder'
        message = f"{action} '{result_path}'. Full match found ({match_kind} + purl)."
    elif bom_entry.purl:
        message = f"{action} '{result_path}'. Found PURL match."
    else:
        message = f"{action} '{result_path}'. Found path match."
    return message


class ScanPostProcessor(ScanossBase):
    """
    Handles post-processing of the scan results
    """

    def __init__(
        self,
        scanoss_settings: ScanossSettings,
        debug: bool = False,
        trace: bool = False,
        quiet: bool = False,
        results: dict = None,
    ):
        """
        Args:
            scanoss_settings (ScanossSettings): Scanoss settings object
            debug (bool, optional): Debug mode. Defaults to False.
            trace (bool, optional): Traces. Defaults to False.
            quiet (bool, optional): Quiet mode. Defaults to False.
            results (dict | str, optional): Results to be processed. Defaults to None.
        """
        super().__init__(debug, trace, quiet)
        self.scanoss_settings = scanoss_settings
        self.results: dict = results
        self.component_info_map: dict = {}

    def load_results(self, raw_results: dict):
        """Load the raw results

        Args:
            raw_results (dict): Raw scan results
        """
        self.results = raw_results
        self._load_component_info()
        return self

    def _load_component_info(self):
        """Create a map of component information from scan results for faster lookup"""
        if not self.results:
            return
        for _, result in self.results.items():
            entry = result[0] if isinstance(result, list) else result
            purls = entry.get('purl', [])
            for purl in purls:
                self.component_info_map[purl] = entry

    def post_process(self):
        """
        Post-process the scan results

        Returns:
            dict: Processed results
        """
        if not self.scanoss_settings:
            return self.results
        if self.scanoss_settings.is_legacy():
            self.print_stderr(
                'Legacy settings file detected. Post-processing is not supported for legacy settings file.'
            )
            return self.results
        self._remove_dismissed_files()
        self._apply_replace_rules()
        return self.results

    def _remove_dismissed_files(self):
        """
        Remove entries from the results based on files and/or purls specified in the SCANOSS settings file
        """
        to_remove_entries = self.scanoss_settings.get_bom_remove()
        if not to_remove_entries:
            return
        self.results = {
            result_path: result
            for result_path, result in self.results.items()
            if not self._should_remove_result(result_path, result, to_remove_entries)
        }

    def _apply_replace_rules(self):
        """
        Apply BOM replace rules from the SCANOSS settings file to the scan results
        """
        to_replace_entries = self.scanoss_settings.get_bom_replace()
        if not to_replace_entries:
            return

        for result_path, result in self.results.items():
            entry = result[0] if isinstance(result, list) else result
            replace_rule = self._find_replace_rule(result_path, entry, to_replace_entries)
            if replace_rule:
                self.results[result_path] = [self._apply_replace_rule(entry, replace_rule)]

    def _apply_replace_rule(self, result: dict, replace_rule: ReplaceRule) -> dict:
        """
        Update the result with the new purl and component information if available,
        otherwise removes the old component information

        Args:
            result (dict): The result to update
            replace_rule (ReplaceRule): The replace rule to apply

        Returns:
            dict: Updated result
        """
        if self.component_info_map.get(replace_rule.replace_with):
            # Only copy component-level fields from the map entry, leaving
            # per-file fields (file, file_hash, lines, matched, etc.) untouched.
            source = self.component_info_map[replace_rule.replace_with]
            for key in ('component', 'vendor', 'url', 'url_hash', 'version', 'latest',
                        'release_date', 'licenses', 'url_stats', 'cryptography',
                        'vulnerabilities', 'provenance', 'dependencies', 'health',
                        'quality'):
                if key in source:
                    result[key] = source[key]
        else:
            try:
                new_component = PackageURL.from_string(replace_rule.replace_with).to_dict()
                new_component_url = purl2url.get_repo_url(replace_rule.replace_with)
            except (ValueError, RuntimeError):
                self.print_stderr(
                    f"ERROR: Issue while replacing: Invalid PURL '{replace_rule.replace_with}'"
                    ' in settings file. Skipping.'
                )
                return result

            result['component'] = new_component.get('name')
            result['url'] = new_component_url
            result['vendor'] = new_component.get('namespace')

            result.pop('file', None)
            result.pop('file_hash', None)
            result.pop('file_url', None)
            result.pop('latest', None)
            result.pop('release_date', None)
            result.pop('source_hash', None)
            result.pop('url_hash', None)
            result.pop('url_stats', None)
            result.pop('version', None)

        if replace_rule.license:
            result['licenses'] = [{'name': replace_rule.license}]
        elif not self.component_info_map.get(replace_rule.replace_with):
            result.pop('licenses', None)

        result['purl'] = [replace_rule.replace_with]
        result['status'] = 'identified'

        return result

    def _find_replace_rule(
        self, result_path: str, result: dict, to_replace_entries: List[ReplaceRule]
    ) -> Optional[ReplaceRule]:
        """
        Check if a result should be replaced based on the SCANOSS settings.
        Uses priority-based matching: most specific rule wins.

        Args:
            result_path (str): Path of the result data
            result (dict): Result to check
            to_replace_entries (List[ReplaceRule]): Replace rules from the settings file

        Returns:
            Optional[ReplaceRule]: The matching replace rule, or None if no match
        """
        result_purls = result.get('purl', [])
        match = find_best_match(result_path, result_purls, to_replace_entries)
        if match and isinstance(match, ReplaceRule) and match.replace_with:
            if self.debug:
                self._print_message(result_path, result_purls, match, 'Replacing')
            return match
        return None

    def _should_remove_result(self, result_path: str, result: dict, to_remove_entries: List[BomEntry]) -> bool:
        """
        Check if a result should be removed based on the SCANOSS settings.
        Uses priority-based matching: most specific rule wins.

        Args:
            result_path (str): Path of the result data
            result (dict): Result to check
            to_remove_entries (List[BomEntry]): BOM entries to remove from the result

        Returns:
            True if the result should be removed
        """
        result = result[0] if isinstance(result, list) else result
        result_purls = result.get('purl', [])
        match = find_best_match(result_path, result_purls, to_remove_entries)
        if match:
            if self.debug:
                self._print_message(result_path, result_purls, match, 'Removing')
            return True
        return False

    def _print_message(self, result_path: str, result_purls: List[str], bom_entry: BomEntry, action: str) -> None:
        """
        Print a message about replacing or removing a result

        Args:
            result_path (str): Path of the scan result
            result_purls (List[str]): Purls from the scan result
            bom_entry (BomEntry): Matched BOM entry
            action (str): Action being performed
        """
        if not self.debug:
            return
        if action == 'Replacing' and isinstance(bom_entry, ReplaceRule):
            message = (
                f'{_get_match_type_message(result_path, bom_entry, action)}\n'
                f'Details:\n'
                f'  - PURLs: {", ".join(result_purls)}\n'
                f'  - Replace with: {bom_entry.replace_with}\n'
                f"  - Path: '{result_path}'"
            )
        else:
            message = (
                f'{_get_match_type_message(result_path, bom_entry, action)}\n'
                f'Details:\n'
                f'  - PURLs: {", ".join(result_purls)}\n'
                f"  - Path: '{result_path}'"
            )
        self.print_debug(message)
#
# End of ScanPostProcessor Class
#
