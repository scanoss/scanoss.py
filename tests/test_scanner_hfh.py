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

import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from scanoss.scanners.scanner_hfh import ScannerHFHPresenter


class TestExtractBestComponents(unittest.TestCase):
    """Tests for ScannerHFHPresenter._extract_best_components"""

    def test_single_result_with_best_component(self):
        hfh_results = [
            {
                'path_id': 'src/lib',
                'components': [
                    {
                        'order': 1,
                        'name': 'best-comp',
                        'versions': [{'version': '1.0.0', 'score': 95}],
                    },
                    {
                        'order': 2,
                        'name': 'other-comp',
                        'versions': [{'version': '2.0.0', 'score': 50}],
                    },
                ],
            }
        ]
        result = ScannerHFHPresenter._extract_best_components(hfh_results)
        self.assertIn('src/lib', result)
        component, version = result['src/lib']
        self.assertEqual(component['name'], 'best-comp')
        self.assertEqual(version['version'], '1.0.0')

    def test_no_order_1_component_skipped(self):
        hfh_results = [
            {
                'path_id': 'src/lib',
                'components': [
                    {'order': 2, 'name': 'comp', 'versions': [{'version': '1.0.0'}]},
                ],
            }
        ]
        result = ScannerHFHPresenter._extract_best_components(hfh_results)
        self.assertEqual(result, {})

    def test_empty_components_skipped(self):
        hfh_results = [{'path_id': 'src/lib', 'components': []}]
        result = ScannerHFHPresenter._extract_best_components(hfh_results)
        self.assertEqual(result, {})

    def test_component_without_versions_skipped(self):
        hfh_results = [
            {
                'path_id': 'src/lib',
                'components': [{'order': 1, 'name': 'comp', 'versions': []}],
            }
        ]
        result = ScannerHFHPresenter._extract_best_components(hfh_results)
        self.assertEqual(result, {})

    def test_default_path_id_is_dot(self):
        hfh_results = [
            {
                'components': [
                    {'order': 1, 'name': 'comp', 'versions': [{'version': '1.0'}]},
                ],
            }
        ]
        result = ScannerHFHPresenter._extract_best_components(hfh_results)
        self.assertIn('.', result)

    def test_multiple_results(self):
        hfh_results = [
            {
                'path_id': 'a',
                'components': [
                    {'order': 1, 'name': 'comp-a', 'versions': [{'version': '1.0'}]},
                ],
            },
            {
                'path_id': 'b',
                'components': [
                    {'order': 1, 'name': 'comp-b', 'versions': [{'version': '2.0'}]},
                ],
            },
        ]
        result = ScannerHFHPresenter._extract_best_components(hfh_results)
        self.assertEqual(len(result), 2)
        self.assertEqual(result['a'][0]['name'], 'comp-a')
        self.assertEqual(result['b'][0]['name'], 'comp-b')

    def test_empty_results_list(self):
        result = ScannerHFHPresenter._extract_best_components([])
        self.assertEqual(result, {})

    def test_first_version_is_selected(self):
        hfh_results = [
            {
                'path_id': '.',
                'components': [
                    {
                        'order': 1,
                        'name': 'comp',
                        'versions': [
                            {'version': '3.0', 'score': 100},
                            {'version': '2.0', 'score': 80},
                        ],
                    },
                ],
            }
        ]
        result = ScannerHFHPresenter._extract_best_components(hfh_results)
        _, version = result['.']
        self.assertEqual(version['version'], '3.0')


class TestFileMatchesPathId(unittest.TestCase):
    """Tests for ScannerHFHPresenter._file_matches_path_id"""

    def test_root_path_matches_all(self):
        self.assertTrue(ScannerHFHPresenter._file_matches_path_id('any/file.py', '.'))

    def test_exact_match(self):
        self.assertTrue(ScannerHFHPresenter._file_matches_path_id('src/lib', 'src/lib'))

    def test_file_under_path_id(self):
        self.assertTrue(
            ScannerHFHPresenter._file_matches_path_id(f'src/lib{os.sep}file.py', 'src/lib')
        )

    def test_file_not_under_path_id(self):
        self.assertFalse(ScannerHFHPresenter._file_matches_path_id('other/file.py', 'src/lib'))

    def test_partial_prefix_no_match(self):
        # 'src/library' should NOT match path_id 'src/lib'
        self.assertFalse(ScannerHFHPresenter._file_matches_path_id('src/library/file.py', 'src/lib'))

    def test_empty_file_path(self):
        self.assertFalse(ScannerHFHPresenter._file_matches_path_id('', 'src/lib'))

    def test_root_path_matches_nested(self):
        self.assertTrue(ScannerHFHPresenter._file_matches_path_id('a/b/c/d.py', '.'))


class TestComputeFileMd5(unittest.TestCase):
    """Tests for ScannerHFHPresenter._compute_file_md5"""

    def _make_presenter(self):
        mock_scanner = MagicMock()
        return ScannerHFHPresenter(mock_scanner)

    def test_correct_md5(self):
        presenter = self._make_presenter()
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b'hello world')
            f.flush()
            path = Path(f.name)
        try:
            expected = hashlib.md5(b'hello world').hexdigest()
            self.assertEqual(presenter._compute_file_md5(path), expected)
        finally:
            os.unlink(path)

    def test_empty_file(self):
        presenter = self._make_presenter()
        with tempfile.NamedTemporaryFile(delete=False) as f:
            path = Path(f.name)
        try:
            expected = hashlib.md5(b'').hexdigest()
            self.assertEqual(presenter._compute_file_md5(path), expected)
        finally:
            os.unlink(path)

    def test_nonexistent_file_returns_empty(self):
        presenter = self._make_presenter()
        path = Path('/nonexistent/file/that/does/not/exist.txt')
        self.assertEqual(presenter._compute_file_md5(path), '')


class TestBuildFileMatchEntry(unittest.TestCase):
    """Tests for ScannerHFHPresenter._build_file_match_entry"""

    @patch('scanoss.scanners.scanner_hfh.purl2url')
    def test_basic_entry(self, mock_purl2url):
        mock_purl2url.get_repo_url.return_value = 'https://github.com/vendor/comp'
        component = {'purl': 'pkg:github/vendor/comp', 'name': 'comp', 'vendor': 'vendor'}
        best_version = {'version': '1.0.0', 'licenses': [{'name': 'MIT'}]}

        entry = ScannerHFHPresenter._build_file_match_entry(
            component, best_version, 'src/file.py', 'abc123', 'https://api.example.com'
        )

        self.assertEqual(entry['id'], 'file')
        self.assertEqual(entry['matched'], '100%')
        self.assertEqual(entry['purl'], ['pkg:github/vendor/comp'])
        self.assertEqual(entry['component'], 'comp')
        self.assertEqual(entry['vendor'], 'vendor')
        self.assertEqual(entry['version'], '1.0.0')
        self.assertEqual(entry['latest'], '1.0.0')
        self.assertEqual(entry['url'], 'https://github.com/vendor/comp')
        self.assertEqual(entry['file'], 'src/file.py')
        self.assertEqual(entry['file_hash'], 'abc123')
        self.assertEqual(entry['file_url'], 'https://api.example.com/file_contents/abc123')
        self.assertEqual(entry['source_hash'], 'abc123')
        self.assertEqual(entry['url_hash'], '')
        self.assertEqual(entry['release_date'], '')
        self.assertEqual(entry['licenses'], [{'name': 'MIT'}])
        self.assertEqual(entry['lines'], 'all')
        self.assertEqual(entry['oss_lines'], 'all')
        self.assertEqual(entry['status'], 'pending')

    @patch('scanoss.scanners.scanner_hfh.purl2url')
    def test_empty_purl(self, mock_purl2url):
        component = {'purl': '', 'name': 'comp', 'vendor': 'vendor'}
        best_version = {'version': '1.0.0', 'licenses': []}

        entry = ScannerHFHPresenter._build_file_match_entry(
            component, best_version, 'file.py', 'hash', 'https://api.example.com'
        )

        self.assertEqual(entry['purl'], [''])
        self.assertEqual(entry['url'], '')
        mock_purl2url.get_repo_url.assert_not_called()

    @patch('scanoss.scanners.scanner_hfh.purl2url')
    def test_missing_fields_use_defaults(self, mock_purl2url):
        mock_purl2url.get_repo_url.return_value = ''
        component = {}
        best_version = {}

        entry = ScannerHFHPresenter._build_file_match_entry(
            component, best_version, 'file.py', 'hash', 'https://api.example.com'
        )

        self.assertEqual(entry['purl'], [''])
        self.assertEqual(entry['component'], '')
        self.assertEqual(entry['vendor'], '')
        self.assertEqual(entry['version'], '')
        self.assertEqual(entry['licenses'], [])

    @patch('scanoss.scanners.scanner_hfh.purl2url')
    def test_purl2url_returns_none(self, mock_purl2url):
        mock_purl2url.get_repo_url.return_value = None
        component = {'purl': 'pkg:github/vendor/comp', 'name': 'comp', 'vendor': 'vendor'}
        best_version = {'version': '1.0.0', 'licenses': []}

        entry = ScannerHFHPresenter._build_file_match_entry(
            component, best_version, 'file.py', 'hash', 'https://api.example.com'
        )

        # url should fallback to '' when purl2url returns None/falsy
        self.assertEqual(entry['url'], '')


if __name__ == '__main__':
    unittest.main()