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
    find_best_match,
)
from scanoss.scanpostprocessor import ScanPostProcessor


class TestMatchesPath(unittest.TestCase):
    """Unit tests for the BomEntry.matches_path method"""

    def test_empty_entry_path_matches_everything(self):
        self.assertTrue(BomEntry(path='').matches_path('src/main.c'))
        self.assertTrue(BomEntry(path=None).matches_path('src/main.c'))
        self.assertTrue(BomEntry(path='').matches_path(''))

    def test_exact_file_match(self):
        self.assertTrue(BomEntry(path='src/main.c').matches_path('src/main.c'))

    def test_exact_file_no_match(self):
        self.assertFalse(BomEntry(path='src/main.c').matches_path('src/other.c'))

    def test_folder_prefix_match(self):
        self.assertTrue(BomEntry(path='src/vendor/').matches_path('src/vendor/lib.c'))
        self.assertTrue(BomEntry(path='src/vendor/').matches_path('src/vendor/sub/deep.c'))

    def test_folder_no_match(self):
        self.assertFalse(BomEntry(path='src/vendor/').matches_path('src/other/lib.c'))
        self.assertFalse(BomEntry(path='src/vendor/').matches_path('src/vendorlib.c'))

    def test_folder_root_prefix(self):
        self.assertTrue(BomEntry(path='src/').matches_path('src/main.c'))
        self.assertTrue(BomEntry(path='src/').matches_path('src/vendor/deep/file.c'))

    def test_exact_path_does_not_prefix_match(self):
        """File paths (no trailing slash) should not do prefix matching"""
        self.assertFalse(BomEntry(path='src/main.c').matches_path('src/main.cpp'))


class TestEntryPriority(unittest.TestCase):
    """Unit tests for the BomEntry.priority property"""

    def test_path_and_purl(self):
        self.assertEqual(BomEntry(path='src/main.c', purl='pkg:npm/vue').priority, 4)

    def test_purl_only(self):
        self.assertEqual(BomEntry(purl='pkg:npm/vue').priority, 2)

    def test_path_only(self):
        self.assertEqual(BomEntry(path='src/vendor/').priority, 1)

    def test_empty_entry(self):
        self.assertEqual(BomEntry().priority, 0)

    def test_empty_strings(self):
        self.assertEqual(BomEntry(path='', purl='').priority, 0)


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
    """Test per-file SBOM context resolution and payload building"""

    def _make_settings(self, settings_data: dict) -> ScanossSettings:
        """Create a ScanossSettings instance from a dict without file I/O"""
        settings = ScanossSettings()
        settings.data = settings_data
        return settings

    # -- get_matching_purls tests --

    def test_get_matching_purls_purl_only(self):
        """Purl-only entries should match any file path"""
        settings = self._make_settings({
            'bom': {
                'include': [
                    {'purl': 'pkg:npm/global'},
                    {'purl': 'pkg:npm/other'},
                ],
            }
        })
        result = settings.get_matching_purls('anything/file.c')
        self.assertIsInstance(result, list)
        self.assertEqual(set(result), {'pkg:npm/global', 'pkg:npm/other'})

    def test_get_matching_purls_folder_scoped(self):
        """Folder-scoped entries should only match files under that folder"""
        settings = self._make_settings({
            'bom': {
                'include': [
                    {'purl': 'pkg:npm/global'},
                    {'path': 'src/vendor/', 'purl': 'pkg:npm/vendor-lib'},
                ],
            }
        })
        # File under vendor/ gets both purls
        result_vendor = settings.get_matching_purls('src/vendor/lib.c')
        self.assertEqual(set(result_vendor), {'pkg:npm/global', 'pkg:npm/vendor-lib'})
        # File outside vendor/ gets only global
        result_other = settings.get_matching_purls('src/core/main.c')
        self.assertEqual(result_other, ['pkg:npm/global'])

    def test_get_matching_purls_no_data(self):
        """Should return empty list when no data"""
        settings = self._make_settings({})
        result = settings.get_matching_purls('src/main.c')
        self.assertEqual(result, [])

    def test_get_matching_purls_no_entries(self):
        """Should return empty list when no include/exclude entries"""
        settings = self._make_settings({
            'bom': {
                'include': [],
                'exclude': [],
            }
        })
        result = settings.get_matching_purls('src/main.c')
        self.assertEqual(result, [])

    def test_get_matching_purls_deduplicates(self):
        """Should not duplicate purls when multiple entries match same purl"""
        settings = self._make_settings({
            'bom': {
                'include': [
                    {'purl': 'pkg:npm/vue'},
                    {'path': 'src/', 'purl': 'pkg:npm/vue'},
                ],
            }
        })
        result = settings.get_matching_purls('src/main.c')
        self.assertEqual(result.count('pkg:npm/vue'), 1)

    def test_get_matching_purls_ordered_by_specificity(self):
        """Should return purls ordered by specificity (most specific first)"""
        settings = self._make_settings({
            'bom': {
                'include': [
                    {'purl': 'pkg:npm/global'},                              # score: 2 (purl only)
                    {'path': 'src/', 'purl': 'pkg:npm/src-lib'},             # score: 4 + 4 = 8
                    {'path': 'src/vendor/', 'purl': 'pkg:npm/vendor-lib'},   # score: 4 + 11 = 15
                ],
            }
        })
        result = settings.get_matching_purls('src/vendor/lib.c')
        # Most specific first: vendor-lib (15), src-lib (8), global (2)
        self.assertEqual(result, ['pkg:npm/vendor-lib', 'pkg:npm/src-lib', 'pkg:npm/global'])

    def test_get_matching_purls_file_path_most_specific(self):
        """File path should be more specific than folder path"""
        settings = self._make_settings({
            'bom': {
                'include': [
                    {'path': 'src/', 'purl': 'pkg:npm/folder-lib'},
                    {'path': 'src/main.c', 'purl': 'pkg:npm/file-lib'},
                ],
            }
        })
        result = settings.get_matching_purls('src/main.c')
        # File path (10 chars) more specific than folder path (4 chars)
        self.assertEqual(result[0], 'pkg:npm/file-lib')

    # -- build_sbom_payload tests --

    def test_build_sbom_payload_identify(self):
        """Should return identify scan type for include entries"""
        settings = self._make_settings({
            'bom': {
                'include': [{'purl': 'pkg:npm/vue'}],
            }
        })
        result = settings.build_sbom_payload(['pkg:npm/vue', 'pkg:npm/react'])
        self.assertIsNotNone(result)
        self.assertEqual(result['scan_type'], 'identify')
        assets = json.loads(result['assets'])
        # Order should be preserved
        self.assertEqual(assets['components'], [{'purl': 'pkg:npm/vue'}, {'purl': 'pkg:npm/react'}])

    def test_build_sbom_payload_blacklist(self):
        """Should return blacklist scan type for exclude entries"""
        settings = self._make_settings({
            'bom': {
                'exclude': [{'purl': 'pkg:npm/excluded'}],
            }
        })
        result = settings.build_sbom_payload(['pkg:npm/excluded'])
        self.assertIsNotNone(result)
        self.assertEqual(result['scan_type'], 'blacklist')

    def test_build_sbom_payload_empty_purls(self):
        """Should return None for empty purls list"""
        settings = self._make_settings({
            'bom': {
                'include': [{'purl': 'pkg:npm/vue'}],
            }
        })
        result = settings.build_sbom_payload([])
        self.assertIsNone(result)

    def test_build_sbom_payload_preserves_order(self):
        """Should preserve the order of purls in the payload"""
        settings = self._make_settings({
            'bom': {
                'include': [{'purl': 'pkg:npm/a'}],
            }
        })
        purls = ['pkg:npm/c', 'pkg:npm/a', 'pkg:npm/b']
        result = settings.build_sbom_payload(purls)
        assets = json.loads(result['assets'])
        self.assertEqual([c['purl'] for c in assets['components']], purls)

    # -- Integration tests (get_matching_purls + build_sbom_payload) --

    def test_folder_scoped_entry_included_when_matching(self):
        """Folder-scoped entry should be included when file matches"""
        settings = self._make_settings({
            'bom': {
                'include': [
                    {'path': 'src/vendor/', 'purl': 'pkg:npm/vue'},
                ],
            }
        })
        purls = settings.get_matching_purls('src/vendor/lib.c')
        result = settings.build_sbom_payload(purls)
        self.assertIsNotNone(result)
        assets = json.loads(result['assets'])
        self.assertEqual([c['purl'] for c in assets['components']], ['pkg:npm/vue'])

    def test_folder_scoped_entry_excluded_when_no_match(self):
        """Folder-scoped entry should not be included when file doesn't match"""
        settings = self._make_settings({
            'bom': {
                'include': [
                    {'path': 'src/vendor/', 'purl': 'pkg:npm/vue'},
                ],
            }
        })
        purls = settings.get_matching_purls('lib/other.c')
        result = settings.build_sbom_payload(purls)
        self.assertIsNone(result)

    def test_mixed_purl_only_and_scoped(self):
        """Purl-only entries always included, scoped entries filtered by path"""
        settings = self._make_settings({
            'bom': {
                'include': [
                    {'purl': 'pkg:npm/global-lib'},
                    {'path': 'src/vendor/', 'purl': 'pkg:npm/vendor-lib'},
                    {'path': 'lib/', 'purl': 'pkg:npm/lib-only'},
                ],
            }
        })
        purls = settings.get_matching_purls('src/vendor/file.c')
        self.assertIn('pkg:npm/global-lib', purls)
        self.assertIn('pkg:npm/vendor-lib', purls)
        self.assertNotIn('pkg:npm/lib-only', purls)


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
        """Path-scoped include: files with different contexts should be
        sent in separate batches with the correct purls each."""
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
        # Context-change flush splits into 2 batches:
        # - vendor batch: {global-lib, vendor-lib}
        # - non-vendor batch: {global-lib} only
        self.assertEqual(len(payloads), 2,
            f'Expected 2 POST calls (different contexts), got {len(payloads)}')

        purl_sets = []
        for payload in payloads:
            self.assertEqual(payload.get('type'), 'identify')
            assets = json.loads(payload.get('assets'))
            purls = frozenset(c['purl'] for c in assets['components'])
            purl_sets.append(purls)

        self.assertIn(frozenset({'pkg:npm/global-lib', 'pkg:npm/vendor-lib'}), purl_sets)
        self.assertIn(frozenset({'pkg:npm/global-lib'}), purl_sets)

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

    # -- Context-change flush tests --

    def test_context_change_flushes_batch(self):
        """Files in folders with different path-scoped purls should be
        sent in separate POST requests with only their matching purls."""
        settings = self._make_settings({
            'bom': {
                'include': [
                    {'purl': 'pkg:npm/global-lib'},
                    {'path': 'src/vendor/', 'purl': 'pkg:npm/vendor-lib'},
                    {'path': 'src/core/', 'purl': 'pkg:npm/core-lib'},
                ],
            }
        })
        self._create_files([
            'src/vendor/a.c',
            'src/core/b.c',
        ])
        scanner, mock_post = self._create_scanner(settings)

        scanner.scan_folder_with_options(self.test_dir)

        self.assertTrue(mock_post.called, 'Expected at least one POST call')
        payloads = self._extract_payloads(mock_post)

        # Should have exactly 2 POST requests (one per folder context)
        self.assertEqual(len(payloads), 2,
            f'Expected exactly 2 POST calls (one per folder context), got {len(payloads)}')

        # Collect the purl sets from each payload
        purl_sets = []
        for payload in payloads:
            self.assertEqual(payload.get('type'), 'identify')
            assets = json.loads(payload.get('assets'))
            purls = frozenset(c['purl'] for c in assets['components'])
            purl_sets.append(purls)

        # One payload should have {global, vendor}, the other {global, core}
        expected_vendor = frozenset({'pkg:npm/global-lib', 'pkg:npm/vendor-lib'})
        expected_core = frozenset({'pkg:npm/global-lib', 'pkg:npm/core-lib'})

        self.assertIn(expected_vendor, purl_sets,
            f'Expected vendor payload with {expected_vendor}, got {purl_sets}')
        self.assertIn(expected_core, purl_sets,
            f'Expected core payload with {expected_core}, got {purl_sets}')

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

    # -- Corner case tests: priority ordering --

    def test_payload_preserves_specificity_order(self):
        """Purls in payload should be ordered by specificity (most specific first)."""
        settings = self._make_settings({
            'bom': {
                'include': [
                    {'purl': 'pkg:npm/global'},                        # score: 2
                    {'path': 'src/', 'purl': 'pkg:npm/src-lib'},       # score: 4 + 4 = 8
                    {'path': 'src/vendor/', 'purl': 'pkg:npm/vendor'}, # score: 4 + 11 = 15
                ],
            }
        })
        self._create_files(['src/vendor/lib.c'])
        scanner, mock_post = self._create_scanner(settings)
        scanner.scan_folder_with_options(self.test_dir)

        payloads = self._extract_payloads(mock_post)
        self.assertEqual(len(payloads), 1)
        assets = json.loads(payloads[0]['assets'])
        purl_order = [c['purl'] for c in assets['components']]
        # Most specific first
        self.assertEqual(purl_order, ['pkg:npm/vendor', 'pkg:npm/src-lib', 'pkg:npm/global'])

    def test_same_context_batches_together(self):
        """Files with identical purl context should batch into single POST."""
        settings = self._make_settings({
            'bom': {
                'include': [
                    {'purl': 'pkg:npm/global'},
                    {'path': 'src/', 'purl': 'pkg:npm/src-lib'},
                ],
            }
        })
        # All files under src/ → same context
        self._create_files(['src/a.c', 'src/b.c', 'src/c.c'])
        scanner, mock_post = self._create_scanner(settings)
        scanner.scan_folder_with_options(self.test_dir)

        payloads = self._extract_payloads(mock_post)
        self.assertEqual(len(payloads), 1, 'Expected single POST for same context')

    def test_nested_folder_deeper_wins(self):
        """Deeper folder rule should produce higher-priority purl in payload."""
        settings = self._make_settings({
            'bom': {
                'include': [
                    {'path': 'src/', 'purl': 'pkg:npm/shallow'},
                    {'path': 'src/vendor/', 'purl': 'pkg:npm/deep'},
                ],
            }
        })
        self._create_files(['src/vendor/lib.c'])
        scanner, mock_post = self._create_scanner(settings)
        scanner.scan_folder_with_options(self.test_dir)

        payloads = self._extract_payloads(mock_post)
        self.assertEqual(len(payloads), 1)
        assets = json.loads(payloads[0]['assets'])
        purl_order = [c['purl'] for c in assets['components']]
        # deep (score 15) before shallow (score 8)
        self.assertEqual(purl_order[0], 'pkg:npm/deep')

    def test_file_path_beats_folder_path_ordering(self):
        """File-specific rule should appear before folder rule for ordering."""
        settings = self._make_settings({
            'bom': {
                'include': [
                    {'path': 'src/', 'purl': 'pkg:npm/folder-lib'},          # score: 8
                    {'path': 'src/main.c', 'purl': 'pkg:npm/file-lib'},      # score: 14
                ],
            }
        })
        self._create_files(['src/main.c'])
        scanner, mock_post = self._create_scanner(settings)
        scanner.scan_folder_with_options(self.test_dir)

        payloads = self._extract_payloads(mock_post)
        self.assertEqual(len(payloads), 1)
        assets = json.loads(payloads[0]['assets'])
        purl_order = [c['purl'] for c in assets['components']]
        self.assertEqual(purl_order[0], 'pkg:npm/file-lib')

    def test_three_contexts_three_posts(self):
        """Files in 3 different folder contexts should result in 3 POSTs."""
        settings = self._make_settings({
            'bom': {
                'include': [
                    {'path': 'vendor/', 'purl': 'pkg:npm/vendor'},
                    {'path': 'core/', 'purl': 'pkg:npm/core'},
                    {'path': 'lib/', 'purl': 'pkg:npm/lib'},
                ],
            }
        })
        self._create_files(['vendor/a.c', 'core/b.c', 'lib/c.c'])
        scanner, mock_post = self._create_scanner(settings)
        scanner.scan_folder_with_options(self.test_dir)

        payloads = self._extract_payloads(mock_post)
        self.assertEqual(len(payloads), 3)

    def test_mixed_matching_and_non_matching(self):
        """Files outside all path rules should have no SBOM, inside should have SBOM."""
        settings = self._make_settings({
            'bom': {
                'include': [
                    {'path': 'vendor/', 'purl': 'pkg:npm/vendor-lib'},
                ],
            }
        })
        self._create_files(['vendor/lib.c', 'src/main.c'])
        scanner, mock_post = self._create_scanner(settings)
        scanner.scan_folder_with_options(self.test_dir)

        payloads = self._extract_payloads(mock_post)
        # 2 batches: one with SBOM (vendor/), one without (src/)
        self.assertEqual(len(payloads), 2)

        has_sbom = [p for p in payloads if 'type' in p]
        no_sbom = [p for p in payloads if 'type' not in p]
        self.assertEqual(len(has_sbom), 1)
        self.assertEqual(len(no_sbom), 1)


if __name__ == '__main__':
    unittest.main()
