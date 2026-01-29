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

from typing import List, Tuple

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
        match_kind = 'folder' if entry_path.endswith('/') else 'file'
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
        scan_settings: ScanossSettings,
        debug: bool = False,
        trace: bool = False,
        quiet: bool = False,
        results: dict = None,
    ):
        """
        Args:
            scan_settings (ScanossSettings): Scan settings object
            debug (bool, optional): Debug mode. Defaults to False.
            trace (bool, optional): Traces. Defaults to False.
            quiet (bool, optional): Quiet mode. Defaults to False.
            results (dict | str, optional): Results to be processed. Defaults to None.
        """
        super().__init__(debug, trace, quiet)
        self.scan_settings = scan_settings
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
            result = result[0] if isinstance(result, list) else result
            purls = result.get('purl', [])
            for purl in purls:
                self.component_info_map[purl] = result

    def post_process(self):
        """
        Post-process the scan results

        Returns:
            dict: Processed results
        """
        if self.scan_settings.is_legacy():
            self.print_stderr(
                'Legacy settings file detected. Post-processing is not supported for legacy settings file.'
            )
            return self.results
        self._remove_dismissed_files()
        self._replace_purls()
        return self.results

    def _remove_dismissed_files(self):
        """
        Remove entries from the results based on files and/or purls specified in the SCANOSS settings file
        """
        to_remove_entries = self.scan_settings.get_bom_remove()
        if not to_remove_entries:
            return
        self.results = {
            result_path: result
            for result_path, result in self.results.items()
            if not self._should_remove_result(result_path, result, to_remove_entries)
        }

    def _replace_purls(self):
        """
        Replace purls in the results based on the SCANOSS settings file
        """
        to_replace_entries = self.scan_settings.get_bom_replace()
        if not to_replace_entries:
            return

        for result_path, result in self.results.items():
            result = result[0] if isinstance(result, list) else result
            should_replace, to_replace_with_purl = self._should_replace_result(result_path, result, to_replace_entries)
            if should_replace:
                self.results[result_path] = [self._update_replaced_result(result, to_replace_with_purl)]

    def _update_replaced_result(self, result: dict, to_replace_with_purl: str) -> dict:
        """
        Update the result with the new purl and component information if available,
        otherwise removes the old component information

        Args:
            result (dict): The result to update
            to_replace_with_purl (str): The purl to replace with

        Returns:
            dict: Updated result
        """

        if self.component_info_map.get(to_replace_with_purl):
            result.update(self.component_info_map[to_replace_with_purl])
        else:
            try:
                new_component = PackageURL.from_string(to_replace_with_purl).to_dict()
                new_component_url = purl2url.get_repo_url(to_replace_with_purl)
            except RuntimeError:
                self.print_stderr(
                    f"ERROR: Issue while replacing: Invalid PURL '{to_replace_with_purl}' in settings file. Skipping."
                )
                return result

            result['component'] = new_component.get('name')
            result['url'] = new_component_url
            result['vendor'] = new_component.get('namespace')

            result.pop('licenses', None)
            result.pop('file', None)
            result.pop('file_hash', None)
            result.pop('file_url', None)
            result.pop('latest', None)
            result.pop('release_date', None)
            result.pop('source_hash', None)
            result.pop('url_hash', None)
            result.pop('url_stats', None)
            result.pop('url_stats', None)
            result.pop('version', None)

        result['purl'] = [to_replace_with_purl]

        return result

    def _should_replace_result(
        self, result_path: str, result: dict, to_replace_entries: List[ReplaceRule]
    ) -> Tuple[bool, str]:
        """
        Check if a result should be replaced based on the SCANOSS settings.
        Uses priority-based matching: most specific rule wins.

        Args:
            result_path (str): Path of the result data
            result (dict): Result to check
            to_replace_entries (List[ReplaceRule]): Replace rules from the settings file

        Returns:
            bool: True if the result should be replaced, False otherwise
            str: The purl to replace with
        """
        result_purls = result.get('purl', [])
        match = find_best_match(result_path, result_purls, to_replace_entries)
        if match and isinstance(match, ReplaceRule) and match.replace_with:
            self._print_message(result_path, result_purls, match, 'Replacing')
            return True, match.replace_with
        return False, None

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
        message = (
            f'{_get_match_type_message(result_path, bom_entry, action)} \n'
            f'Details:\n'
            f'  - PURLs: {", ".join(result_purls)}\n'
            f"  - Path: '{result_path}'\n"
        )
        if action == 'Replacing' and isinstance(bom_entry, ReplaceRule):
            message += f" - {action} with '{bom_entry.replace_with}'"
        self.print_debug(message)


#
# End of ScanPostProcessor Class
#
