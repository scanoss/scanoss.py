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

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from scanoss.scanner import Scanner
from scanoss.scanoss_settings import (
    BomEntry,
    ReplaceRule,
    ScanossSettings,
    entry_priority,
    find_best_match,
    matches_path,
)
from scanoss.scanpostprocessor import ScanPostProcessor


class TestMatchesPath(unittest.TestCase):
    """Unit tests for the matches_path helper function"""

    def test_empty_entry_path_matches_everything(self):
        self.assertTrue(matches_path('', 'src/main.c'))
        self.assertTrue(matches_path('', ''))

    def test_exact_file_match(self):
        self.assertTrue(matches_path('src/main.c', 'src/main.c'))

    def test_exact_file_no_match(self):
        self.assertFalse(matches_path('src/main.c', 'src/other.c'))

    def test_folder_prefix_match(self):
        self.assertTrue(matches_path('src/vendor/', 'src/vendor/lib.c'))
        self.assertTrue(matches_path('src/vendor/', 'src/vendor/sub/deep.c'))

    def test_folder_no_match(self):
        self.assertFalse(matches_path('src/vendor/', 'src/other/lib.c'))
        self.assertFalse(matches_path('src/vendor/', 'src/vendorlib.c'))

    def test_folder_root_prefix(self):
        self.assertTrue(matches_path('src/', 'src/main.c'))
        self.assertTrue(matches_path('src/', 'src/vendor/deep/file.c'))

    def test_exact_path_does_not_prefix_match(self):
        """File paths (no trailing slash) should not do prefix matching"""
        self.assertFalse(matches_path('src/main.c', 'src/main.cpp'))


class TestEntryPriority(unittest.TestCase):
    """Unit tests for the entry_priority helper function"""

    def test_path_and_purl(self):
        self.assertEqual(entry_priority(BomEntry(path='src/main.c', purl='pkg:npm/vue')), 4)

    def test_purl_only(self):
        self.assertEqual(entry_priority(BomEntry(purl='pkg:npm/vue')), 2)

    def test_path_only(self):
        self.assertEqual(entry_priority(BomEntry(path='src/vendor/')), 1)

    def test_empty_entry(self):
        self.assertEqual(entry_priority(BomEntry()), 0)

    def test_empty_strings(self):
        self.assertEqual(entry_priority(BomEntry(path='', purl='')), 0)


class TestFindBestMatch(unittest.TestCase):
    """Unit tests for the find_best_match helper function"""

    def test_no_entries(self):
        result = find_best_match('src/main.c', ['pkg:npm/vue'], [])
        self.assertIsNone(result)

    def test_purl_only_match(self):
        entries = [BomEntry(purl='pkg:npm/vue')]
        result = find_best_match('src/main.c', ['pkg:npm/vue'], entries)
        self.assertEqual(result, entries[0])

    def test_path_only_match(self):
        entries = [BomEntry(path='src/vendor/')]
        result = find_best_match('src/vendor/lib.c', ['pkg:npm/vue'], entries)
        self.assertEqual(result, entries[0])

    def test_full_match_beats_purl_only(self):
        entries = [
            BomEntry(purl='pkg:npm/vue'),
            BomEntry(path='src/main.c', purl='pkg:npm/vue'),
        ]
        result = find_best_match('src/main.c', ['pkg:npm/vue'], entries)
        self.assertEqual(result, entries[1])

    def test_full_match_beats_path_only(self):
        entries = [
            BomEntry(path='src/'),
            BomEntry(path='src/main.c', purl='pkg:npm/vue'),
        ]
        result = find_best_match('src/main.c', ['pkg:npm/vue'], entries)
        self.assertEqual(result, entries[1])

    def test_longer_path_wins_on_tie(self):
        entries = [
            BomEntry(path='src/', purl='pkg:npm/vue'),
            BomEntry(path='src/vendor/', purl='pkg:npm/vue'),
        ]
        result = find_best_match('src/vendor/lib.c', ['pkg:npm/vue'], entries)
        self.assertEqual(result, entries[1])

    def test_no_match_when_purl_not_in_result(self):
        entries = [BomEntry(purl='pkg:npm/react')]
        result = find_best_match('src/main.c', ['pkg:npm/vue'], entries)
        self.assertIsNone(result)

    def test_no_match_when_path_does_not_match(self):
        entries = [BomEntry(path='lib/', purl='pkg:npm/vue')]
        result = find_best_match('src/main.c', ['pkg:npm/vue'], entries)
        self.assertIsNone(result)

    def test_path_only_entry_matches_without_purl(self):
        """Path-only remove entries should match regardless of result purls"""
        entries = [BomEntry(path='src/vendor/')]
        result = find_best_match('src/vendor/lib.c', [], entries)
        self.assertEqual(result, entries[0])

    def test_skip_entries_with_no_path_and_no_purl(self):
        entries = [BomEntry(comment='just a comment')]
        result = find_best_match('src/main.c', ['pkg:npm/vue'], entries)
        self.assertIsNone(result)

    def test_order_independent(self):
        """Best match should be found regardless of entry order"""
        entries_a = [
            BomEntry(purl='pkg:npm/vue'),
            BomEntry(path='src/main.c', purl='pkg:npm/vue'),
        ]
        entries_b = [
            BomEntry(path='src/main.c', purl='pkg:npm/vue'),
            BomEntry(purl='pkg:npm/vue'),
        ]
        result_a = find_best_match('src/main.c', ['pkg:npm/vue'], entries_a)
        result_b = find_best_match('src/main.c', ['pkg:npm/vue'], entries_b)
        self.assertEqual(result_a.path, 'src/main.c')
        self.assertEqual(result_b.path, 'src/main.c')


class TestPostProcessorFolderMatching(unittest.TestCase):
    """Test folder-level matching in the post-processor (remove and replace)"""

    def _make_settings(self, settings_data: dict) -> ScanossSettings:
        """Create a ScanossSettings instance from a dict without file I/O"""
        settings = ScanossSettings()
        settings.data = settings_data
        return settings

    def test_remove_by_folder_path(self):
        """Should remove all results under a folder path"""
        settings = self._make_settings({
            'bom': {
                'remove': [{'path': 'src/vendor/', 'purl': 'pkg:npm/vue'}],
            }
        })
        results = {
            'src/vendor/lib.c': [{'purl': ['pkg:npm/vue']}],
            'src/vendor/sub/deep.c': [{'purl': ['pkg:npm/vue']}],
            'src/main.c': [{'purl': ['pkg:npm/vue']}],
        }
        processor = ScanPostProcessor(settings)
        processed = processor.load_results(results).post_process()
        self.assertNotIn('src/vendor/lib.c', processed)
        self.assertNotIn('src/vendor/sub/deep.c', processed)
        self.assertIn('src/main.c', processed)

    def test_remove_by_path_only(self):
        """Should remove by path only (no purl required)"""
        settings = self._make_settings({
            'bom': {
                'remove': [{'path': 'src/vendor/'}],
            }
        })
        results = {
            'src/vendor/lib.c': [{'purl': ['pkg:npm/vue']}],
            'src/main.c': [{'purl': ['pkg:npm/react']}],
        }
        processor = ScanPostProcessor(settings)
        processed = processor.load_results(results).post_process()
        self.assertNotIn('src/vendor/lib.c', processed)
        self.assertIn('src/main.c', processed)

    def test_replace_by_folder_path(self):
        """Should replace purls for all results under a folder"""
        settings = self._make_settings({
            'bom': {
                'replace': [{
                    'path': 'src/vendor/',
                    'purl': 'pkg:npm/old-lib',
                    'replace_with': 'pkg:npm/new-lib',
                }],
            }
        })
        results = {
            'src/vendor/file.c': [{'purl': ['pkg:npm/old-lib']}],
            'src/vendor/sub/deep.c': [{'purl': ['pkg:npm/old-lib']}],
            'src/main.c': [{'purl': ['pkg:npm/old-lib']}],
        }
        processor = ScanPostProcessor(settings)
        processed = processor.load_results(results).post_process()
        self.assertEqual(processed['src/vendor/file.c'][0]['purl'], ['pkg:npm/new-lib'])
        self.assertEqual(processed['src/vendor/sub/deep.c'][0]['purl'], ['pkg:npm/new-lib'])
        self.assertEqual(processed['src/main.c'][0]['purl'], ['pkg:npm/old-lib'])

    def test_priority_specific_file_beats_folder(self):
        """A file+purl rule should take priority over a folder+purl rule"""
        settings = self._make_settings({
            'bom': {
                'replace': [
                    {
                        'path': 'src/vendor/',
                        'purl': 'pkg:npm/lib',
                        'replace_with': 'pkg:npm/folder-replacement',
                    },
                    {
                        'path': 'src/vendor/special.c',
                        'purl': 'pkg:npm/lib',
                        'replace_with': 'pkg:npm/file-replacement',
                    },
                ],
            }
        })
        results = {
            'src/vendor/special.c': [{'purl': ['pkg:npm/lib']}],
            'src/vendor/other.c': [{'purl': ['pkg:npm/lib']}],
        }
        processor = ScanPostProcessor(settings)
        processed = processor.load_results(results).post_process()
        # File rule (score 4, longer path) should beat folder rule (score 4, shorter path)
        self.assertEqual(processed['src/vendor/special.c'][0]['purl'], ['pkg:npm/file-replacement'])
        self.assertEqual(processed['src/vendor/other.c'][0]['purl'], ['pkg:npm/folder-replacement'])

    def test_priority_purl_plus_path_beats_purl_only(self):
        """A purl+path rule should take priority over a purl-only rule"""
        settings = self._make_settings({
            'bom': {
                'remove': [
                    {'purl': 'pkg:npm/lib'},  # purl-only, score 2 - should NOT match
                ],
                'replace': [
                    {
                        'path': 'src/',
                        'purl': 'pkg:npm/lib',
                        'replace_with': 'pkg:npm/replacement',
                    },
                ],
            }
        })
        # Remove and replace operate independently on results
        results = {
            'src/main.c': [{'purl': ['pkg:npm/lib']}],
        }
        processor = ScanPostProcessor(settings)
        processed = processor.load_results(results).post_process()
        # The purl-only remove rule matches, so it should be removed
        self.assertNotIn('src/main.c', processed)

    def test_deeper_folder_wins(self):
        """A deeper folder rule should take priority over a shallower one"""
        settings = self._make_settings({
            'bom': {
                'replace': [
                    {
                        'path': 'src/',
                        'purl': 'pkg:npm/lib',
                        'replace_with': 'pkg:npm/shallow-replacement',
                    },
                    {
                        'path': 'src/vendor/',
                        'purl': 'pkg:npm/lib',
                        'replace_with': 'pkg:npm/deep-replacement',
                    },
                ],
            }
        })
        results = {
            'src/vendor/file.c': [{'purl': ['pkg:npm/lib']}],
            'src/main.c': [{'purl': ['pkg:npm/lib']}],
        }
        processor = ScanPostProcessor(settings)
        processed = processor.load_results(results).post_process()
        self.assertEqual(processed['src/vendor/file.c'][0]['purl'], ['pkg:npm/deep-replacement'])
        self.assertEqual(processed['src/main.c'][0]['purl'], ['pkg:npm/shallow-replacement'])


class TestSbomForBatch(unittest.TestCase):
    """Test per-batch SBOM context resolution"""

    def _make_settings(self, settings_data: dict) -> ScanossSettings:
        """Create a ScanossSettings instance from a dict without file I/O"""
        settings = ScanossSettings()
        settings.data = settings_data
        return settings

    def test_purl_only_entries_always_included(self):
        """Purl-only include entries should be sent with every batch"""
        settings = self._make_settings({
            'bom': {
                'include': [
                    {'purl': 'pkg:npm/vue'},
                    {'purl': 'pkg:npm/react'},
                ],
            }
        })
        result = settings.get_sbom_for_batch(['any/file.c'])
        self.assertIsNotNone(result)
        assets = json.loads(result['assets'])
        purls = [c['purl'] for c in assets['components']]
        self.assertIn('pkg:npm/vue', purls)
        self.assertIn('pkg:npm/react', purls)
        self.assertEqual(result['scan_type'], 'identify')

    def test_folder_scoped_entry_included_when_matching(self):
        """Folder-scoped entry should be included when batch contains matching files"""
        settings = self._make_settings({
            'bom': {
                'include': [
                    {'path': 'src/vendor/', 'purl': 'pkg:npm/vue'},
                ],
            }
        })
        result = settings.get_sbom_for_batch(['src/vendor/lib.c'])
        self.assertIsNotNone(result)
        assets = json.loads(result['assets'])
        purls = [c['purl'] for c in assets['components']]
        self.assertIn('pkg:npm/vue', purls)

    def test_folder_scoped_entry_excluded_when_no_match(self):
        """Folder-scoped entry should not be included when no batch files match"""
        settings = self._make_settings({
            'bom': {
                'include': [
                    {'path': 'src/vendor/', 'purl': 'pkg:npm/vue'},
                ],
            }
        })
        result = settings.get_sbom_for_batch(['lib/other.c'])
        self.assertIsNone(result)

    def test_file_scoped_entry_included_when_exact_match(self):
        """File-scoped entry should be included when exact file is in batch"""
        settings = self._make_settings({
            'bom': {
                'include': [
                    {'path': 'src/main.c', 'purl': 'pkg:npm/vue'},
                ],
            }
        })
        result = settings.get_sbom_for_batch(['src/main.c', 'src/other.c'])
        self.assertIsNotNone(result)
        assets = json.loads(result['assets'])
        purls = [c['purl'] for c in assets['components']]
        self.assertIn('pkg:npm/vue', purls)

    def test_file_scoped_entry_excluded_when_no_match(self):
        """File-scoped entry should not be included when file is not in batch"""
        settings = self._make_settings({
            'bom': {
                'include': [
                    {'path': 'src/main.c', 'purl': 'pkg:npm/vue'},
                ],
            }
        })
        result = settings.get_sbom_for_batch(['src/other.c'])
        self.assertIsNone(result)

    def test_mixed_purl_only_and_scoped(self):
        """Purl-only entries always included, scoped entries filtered"""
        settings = self._make_settings({
            'bom': {
                'include': [
                    {'purl': 'pkg:npm/global-lib'},
                    {'path': 'src/vendor/', 'purl': 'pkg:npm/vendor-lib'},
                    {'path': 'lib/', 'purl': 'pkg:npm/lib-only'},
                ],
            }
        })
        result = settings.get_sbom_for_batch(['src/vendor/file.c'])
        self.assertIsNotNone(result)
        assets = json.loads(result['assets'])
        purls = [c['purl'] for c in assets['components']]
        self.assertIn('pkg:npm/global-lib', purls)
        self.assertIn('pkg:npm/vendor-lib', purls)
        self.assertNotIn('pkg:npm/lib-only', purls)

    def test_exclude_entries(self):
        """Exclude entries should use blacklist scan type"""
        settings = self._make_settings({
            'bom': {
                'exclude': [
                    {'purl': 'pkg:npm/excluded'},
                ],
            }
        })
        result = settings.get_sbom_for_batch(['any/file.c'])
        self.assertIsNotNone(result)
        self.assertEqual(result['scan_type'], 'blacklist')
        assets = json.loads(result['assets'])
        purls = [c['purl'] for c in assets['components']]
        self.assertIn('pkg:npm/excluded', purls)

    def test_no_entries_returns_none(self):
        """Should return None when no include or exclude entries exist"""
        settings = self._make_settings({
            'bom': {
                'include': [],
                'exclude': [],
            }
        })
        result = settings.get_sbom_for_batch(['src/main.c'])
        self.assertIsNone(result)

    def test_no_data_returns_none(self):
        """Should return None when settings have no data"""
        settings = self._make_settings({})
        result = settings.get_sbom_for_batch(['src/main.c'])
        self.assertIsNone(result)

    def test_deduplicates_purls(self):
        """Should not duplicate purls when multiple entries match"""
        settings = self._make_settings({
            'bom': {
                'include': [
                    {'purl': 'pkg:npm/vue'},
                    {'path': 'src/', 'purl': 'pkg:npm/vue'},
                ],
            }
        })
        result = settings.get_sbom_for_batch(['src/main.c'])
        self.assertIsNotNone(result)
        assets = json.loads(result['assets'])
        purls = [c['purl'] for c in assets['components']]
        self.assertEqual(purls.count('pkg:npm/vue'), 1)


class TestExtractFilePathsFromWfp(unittest.TestCase):
    """Test WFP file path extraction"""

    def test_extract_single_file(self):
        from scanoss.scanner import Scanner
        wfp = 'file=abc123,1024,src/main.c\n4=abcdef\n'
        paths = Scanner._extract_file_paths_from_wfp(wfp)
        self.assertEqual(paths, ['src/main.c'])

    def test_extract_multiple_files(self):
        from scanoss.scanner import Scanner
        wfp = (
            'file=abc123,1024,src/main.c\n4=abcdef\n'
            'file=def456,2048,src/vendor/lib.c\n4=ghijkl\n'
        )
        paths = Scanner._extract_file_paths_from_wfp(wfp)
        self.assertEqual(paths, ['src/main.c', 'src/vendor/lib.c'])

    def test_extract_empty_wfp(self):
        from scanoss.scanner import Scanner
        paths = Scanner._extract_file_paths_from_wfp('')
        self.assertEqual(paths, [])


class TestScannerSbomPayload(unittest.TestCase):
    """End-to-end tests: verify Scanner sends the correct SBOM payload in HTTP POST requests"""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def _create_files(self, file_paths):
        """Create test files in self.test_dir with enough content for WFP generation."""
        for rel_path in file_paths:
            abs_path = os.path.join(self.test_dir, rel_path)
            os.makedirs(os.path.dirname(abs_path), exist_ok=True)
            with open(abs_path, 'w') as f:
                f.write('/* generated test content */\n' * 20)

    def _make_settings(self, settings_data):
        """Create ScanossSettings from a dict without file I/O."""
        settings = ScanossSettings()
        settings.data = settings_data
        settings.settings_file_type = 'new'
        return settings

    def _create_scanner(self, settings=None):
        """Create a Scanner with mocked session.post.

        Returns:
            (scanner, mock_post) tuple
        """
        scanner = Scanner(
            scan_settings=settings,
            nb_threads=1,
            quiet=True,
            scan_options=3,  # FILES + SNIPPETS, no deps
        )

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.ok = True
        mock_response.json.return_value = {}
        mock_response.text = '{}'

        mock_post = MagicMock(return_value=mock_response)
        scanner.scanoss_api.session.post = mock_post

        return scanner, mock_post

    def _extract_payloads(self, mock_post):
        """Extract form_data dicts from all session.post calls."""
        payloads = []
        for call in mock_post.call_args_list:
            form_data = call.kwargs.get('data', {})
            payloads.append(form_data)
        return payloads

    # -- SBOM tests: purl-only entries --

    def test_sbom_include_sent_in_post(self):
        """When purl-only include entries exist, every POST should contain
        type='identify' and the correct purls in assets."""
        settings = self._make_settings({
            'bom': {
                'include': [
                    {'purl': 'pkg:npm/vue@2.6.12'},
                    {'purl': 'pkg:npm/react@17.0.0'},
                ],
            }
        })
        self._create_files(['src/main.c', 'src/lib.c'])
        scanner, mock_post = self._create_scanner(settings)

        scanner.scan_folder_with_options(self.test_dir)

        self.assertTrue(mock_post.called, 'Expected at least one POST call')
        payloads = self._extract_payloads(mock_post)
        for payload in payloads:
            self.assertEqual(payload.get('type'), 'identify')
            assets = json.loads(payload.get('assets'))
            purls = {c['purl'] for c in assets['components']}
            self.assertIn('pkg:npm/vue@2.6.12', purls)
            self.assertIn('pkg:npm/react@17.0.0', purls)

    def test_sbom_exclude_sent_as_blacklist(self):
        """When purl-only exclude entries exist, every POST should contain
        type='blacklist' and the correct purls in assets."""
        settings = self._make_settings({
            'bom': {
                'exclude': [
                    {'purl': 'pkg:npm/unwanted@1.0.0'},
                ],
            }
        })
        self._create_files(['src/main.c'])
        scanner, mock_post = self._create_scanner(settings)

        scanner.scan_folder_with_options(self.test_dir)

        self.assertTrue(mock_post.called, 'Expected at least one POST call')
        payloads = self._extract_payloads(mock_post)
        for payload in payloads:
            self.assertEqual(payload.get('type'), 'blacklist')
            assets = json.loads(payload.get('assets'))
            purls = {c['purl'] for c in assets['components']}
            self.assertIn('pkg:npm/unwanted@1.0.0', purls)

    def test_no_bom_entries_no_sbom_in_payload(self):
        """When settings have empty BOM lists, POST should have no type/assets."""
        settings = self._make_settings({
            'bom': {
                'include': [],
                'exclude': [],
            }
        })
        self._create_files(['src/main.c'])
        scanner, mock_post = self._create_scanner(settings)

        scanner.scan_folder_with_options(self.test_dir)

        self.assertTrue(mock_post.called, 'Expected at least one POST call')
        payloads = self._extract_payloads(mock_post)
        for payload in payloads:
            self.assertNotIn('type', payload)
            self.assertNotIn('assets', payload)

    # -- SBOM tests: path-scoped entries --

    def test_sbom_path_scoped_include(self):
        """Path-scoped include: batch with matching files should include
        both purl-only and scoped purls."""
        settings = self._make_settings({
            'bom': {
                'include': [
                    {'purl': 'pkg:npm/global-lib'},
                    {'path': 'src/vendor/', 'purl': 'pkg:npm/vendor-lib'},
                ],
            }
        })
        self._create_files(['src/vendor/lib.c', 'src/main.c'])
        scanner, mock_post = self._create_scanner(settings)

        scanner.scan_folder_with_options(self.test_dir)

        self.assertTrue(mock_post.called, 'Expected at least one POST call')
        payloads = self._extract_payloads(mock_post)
        # With both files in one batch, vendor/lib.c triggers the scoped entry
        for payload in payloads:
            self.assertEqual(payload.get('type'), 'identify')
            assets = json.loads(payload.get('assets'))
            purls = {c['purl'] for c in assets['components']}
            self.assertIn('pkg:npm/global-lib', purls)
            self.assertIn('pkg:npm/vendor-lib', purls)

    def test_sbom_no_matching_paths(self):
        """Path-scoped include with no matching files: POST should have no type/assets."""
        settings = self._make_settings({
            'bom': {
                'include': [
                    {'path': 'vendor/', 'purl': 'pkg:npm/vendor-only'},
                ],
            }
        })
        # Files are NOT under vendor/
        self._create_files(['src/main.c'])
        scanner, mock_post = self._create_scanner(settings)

        scanner.scan_folder_with_options(self.test_dir)

        self.assertTrue(mock_post.called, 'Expected at least one POST call')
        payloads = self._extract_payloads(mock_post)
        for payload in payloads:
            self.assertNotIn('type', payload)
            self.assertNotIn('assets', payload)

    def test_sbom_exclude_path_scoped(self):
        """Path-scoped exclude: matching batch should contain type='blacklist'."""
        settings = self._make_settings({
            'bom': {
                'exclude': [
                    {'path': 'src/', 'purl': 'pkg:npm/blocked'},
                ],
            }
        })
        self._create_files(['src/main.c'])
        scanner, mock_post = self._create_scanner(settings)

        scanner.scan_folder_with_options(self.test_dir)

        self.assertTrue(mock_post.called, 'Expected at least one POST call')
        payloads = self._extract_payloads(mock_post)
        for payload in payloads:
            self.assertEqual(payload.get('type'), 'blacklist')
            assets = json.loads(payload.get('assets'))
            purls = {c['purl'] for c in assets['components']}
            self.assertIn('pkg:npm/blocked', purls)

    # -- No settings test --

    def test_no_settings_no_sbom_in_payload(self):
        """When Scanner has no scan_settings, POST should have no type/assets."""
        self._create_files(['src/main.c'])
        scanner, mock_post = self._create_scanner(settings=None)

        scanner.scan_folder_with_options(self.test_dir)

        self.assertTrue(mock_post.called, 'Expected at least one POST call')
        payloads = self._extract_payloads(mock_post)
        for payload in payloads:
            self.assertNotIn('type', payload)
            self.assertNotIn('assets', payload)


if __name__ == '__main__':
    unittest.main()
