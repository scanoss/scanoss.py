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

import os
import unittest
from pathlib import Path

from src.scanoss.scan_settings_builder import (ScanSettingsBuilder)
from src.scanoss.scanoss_settings import ScanossSettings


class TestScanSettingsBuilder(unittest.TestCase):
    """Tests for the ScanSettingsBuilder class."""

    script_dir = os.path.dirname(os.path.abspath(__file__))
    scan_settings_path = Path(script_dir, 'data', 'scanoss.json').resolve()
    scan_settings = ScanossSettings(filepath=scan_settings_path)

    # =========================================================================
    # Test initialization
    # =========================================================================

    def test_init_with_none_settings(self):
        """Test initialization with None settings."""
        builder = ScanSettingsBuilder(None)

        self.assertIsNone(builder.scanoss_settings)
        self.assertIsNone(builder.proxy)
        self.assertIsNone(builder.url)
        self.assertFalse(builder.ignore_cert_errors)
        self.assertIsNone(builder.min_snippet_hits)
        self.assertIsNone(builder.min_snippet_lines)
        self.assertIsNone(builder.honour_file_exts)
        self.assertIsNone(builder.ranking)
        self.assertIsNone(builder.ranking_threshold)

    def test_init_with_settings(self):
        """Test initialization with settings object."""
        builder = ScanSettingsBuilder(self.scan_settings)

        self.assertEqual(builder.scanoss_settings, self.scan_settings)

    # =========================================================================
    # Test static helper methods
    # =========================================================================

    def test_str_to_bool_with_none(self):
        """Test _str_to_bool returns None for None input."""
        self.assertIsNone(ScanSettingsBuilder._str_to_bool(None))

    def test_str_to_bool_with_true_string(self):
        """Test _str_to_bool converts 'true' to True."""
        self.assertTrue(ScanSettingsBuilder._str_to_bool('true'))
        self.assertTrue(ScanSettingsBuilder._str_to_bool('True'))
        self.assertTrue(ScanSettingsBuilder._str_to_bool('TRUE'))

    def test_str_to_bool_with_false_string(self):
        """Test _str_to_bool converts 'false' to False."""
        self.assertFalse(ScanSettingsBuilder._str_to_bool('false'))
        self.assertFalse(ScanSettingsBuilder._str_to_bool('False'))
        self.assertFalse(ScanSettingsBuilder._str_to_bool('FALSE'))

    def test_str_to_bool_with_bool_input(self):
        """Test _str_to_bool passes through bool values."""
        self.assertTrue(ScanSettingsBuilder._str_to_bool(True))
        self.assertFalse(ScanSettingsBuilder._str_to_bool(False))

    def test_merge_with_priority_file_snippet_wins(self):
        """Test _merge_with_priority returns file_snippet value when present (highest priority)."""
        result = ScanSettingsBuilder._merge_with_priority('cli', 'file_snippet', 'root')
        self.assertEqual(result, 'file_snippet')

    def test_merge_with_priority_root_second(self):
        """Test _merge_with_priority returns root when file_snippet is None."""
        result = ScanSettingsBuilder._merge_with_priority('cli', None, 'root')
        self.assertEqual(result, 'root')

    def test_merge_with_priority_cli_fallback(self):
        """Test _merge_with_priority returns CLI when others are None."""
        result = ScanSettingsBuilder._merge_with_priority('cli', None, None)
        self.assertEqual(result, 'cli')

    def test_merge_with_priority_all_none(self):
        """Test _merge_with_priority returns None when all are None."""
        result = ScanSettingsBuilder._merge_with_priority(None, None, None)
        self.assertIsNone(result)

    def test_merge_cli_with_settings_settings_wins(self):
        """Test _merge_cli_with_settings returns settings value when present (highest priority)."""
        result = ScanSettingsBuilder._merge_cli_with_settings('cli', 'settings')
        self.assertEqual(result, 'settings')

    def test_merge_cli_with_settings_cli_fallback(self):
        """Test _merge_cli_with_settings returns CLI when settings is None."""
        result = ScanSettingsBuilder._merge_cli_with_settings('cli', None)
        self.assertEqual(result, 'cli')

    # =========================================================================
    # Test with_proxy
    # =========================================================================

    def test_with_proxy_cli_only(self):
        """Test with_proxy uses CLI value when no settings."""
        builder = ScanSettingsBuilder(None)
        result = builder.with_proxy('http://cli-proxy:8080')

        self.assertEqual(builder.proxy, 'http://cli-proxy:8080')
        self.assertEqual(result, builder)  # Test chaining

    def test_with_proxy_from_file_snippet(self):
        """Test with_proxy uses file_snippet.proxy.host when CLI is None."""
        builder = ScanSettingsBuilder(self.scan_settings)
        builder.with_proxy(None)

        # file_snippet.proxy.host = "http://file-snippet-proxy:8080"
        self.assertEqual(builder.proxy, 'http://file-snippet-proxy:8080')

    def test_with_proxy_settings_overrides_cli(self):
        """Test with_proxy settings value overrides CLI."""
        builder = ScanSettingsBuilder(self.scan_settings)
        builder.with_proxy('http://cli-proxy:8080')

        # file_snippet.proxy.host = "http://file-snippet-proxy:8080" takes priority
        self.assertEqual(builder.proxy, 'http://file-snippet-proxy:8080')

    # =========================================================================
    # Test with_url
    # =========================================================================

    def test_with_url_cli_only(self):
        """Test with_url uses CLI value when no settings."""
        builder = ScanSettingsBuilder(None)
        builder.with_url('https://cli-api.example.com')

        self.assertEqual(builder.url, 'https://cli-api.example.com')

    def test_with_url_from_file_snippet(self):
        """Test with_url uses file_snippet.http_config.base_uri."""
        builder = ScanSettingsBuilder(self.scan_settings)
        builder.with_url(None)

        # file_snippet.http_config.base_uri = "https://file-snippet-api.scanoss.com"
        self.assertEqual(builder.url, 'https://file-snippet-api.scanoss.com')

    def test_with_url_settings_overrides_cli(self):
        """Test with_url settings value overrides CLI."""
        builder = ScanSettingsBuilder(self.scan_settings)
        builder.with_url('https://cli-api.com')

        # file_snippet.http_config.base_uri = "https://file-snippet-api.scanoss.com" takes priority
        self.assertEqual(builder.url, 'https://file-snippet-api.scanoss.com')

    # =========================================================================
    # Test with_ignore_cert_errors
    # =========================================================================

    def test_with_ignore_cert_errors_defaults_to_false(self):
        """Test with_ignore_cert_errors defaults to False."""
        builder = ScanSettingsBuilder(None)
        builder.with_ignore_cert_errors(False)

        self.assertFalse(builder.ignore_cert_errors)

    def test_with_ignore_cert_errors_cli_true(self):
        """Test with_ignore_cert_errors with CLI True."""
        builder = ScanSettingsBuilder(None)
        builder.with_ignore_cert_errors(True)

        self.assertTrue(builder.ignore_cert_errors)

    def test_with_ignore_cert_errors_from_file_snippet(self):
        """Test with_ignore_cert_errors from file_snippet settings."""
        builder = ScanSettingsBuilder(self.scan_settings)
        builder.with_ignore_cert_errors(False)

        # file_snippet.http_config.ignore_cert_errors = true
        self.assertTrue(builder.ignore_cert_errors)

    def test_with_ignore_cert_errors_cli_true_overrides(self):
        """Test with_ignore_cert_errors CLI True overrides settings."""
        builder = ScanSettingsBuilder(self.scan_settings)
        builder.with_ignore_cert_errors(True)

        self.assertTrue(builder.ignore_cert_errors)

    # =========================================================================
    # Test with_min_snippet_hits
    # =========================================================================

    def test_with_min_snippet_hits_cli_only(self):
        """Test with_min_snippet_hits uses CLI value."""
        builder = ScanSettingsBuilder(None)
        builder.with_min_snippet_hits(5)

        self.assertEqual(builder.min_snippet_hits, 5)

    def test_with_min_snippet_hits_from_settings(self):
        """Test with_min_snippet_hits from settings."""
        builder = ScanSettingsBuilder(self.scan_settings)
        builder.with_min_snippet_hits(None)

        # file_snippet.min_snippet_hits = 10
        self.assertEqual(builder.min_snippet_hits, 10)

    def test_with_min_snippet_hits_settings_overrides_cli(self):
        """Test with_min_snippet_hits settings overrides CLI."""
        builder = ScanSettingsBuilder(self.scan_settings)
        builder.with_min_snippet_hits(5)

        # file_snippet.min_snippet_hits = 10 takes priority
        self.assertEqual(builder.min_snippet_hits, 10)

    # =========================================================================
    # Test with_min_snippet_lines
    # =========================================================================

    def test_with_min_snippet_lines_cli_only(self):
        """Test with_min_snippet_lines uses CLI value."""
        builder = ScanSettingsBuilder(None)
        builder.with_min_snippet_lines(3)

        self.assertEqual(builder.min_snippet_lines, 3)

    def test_with_min_snippet_lines_from_settings(self):
        """Test with_min_snippet_lines from settings."""
        builder = ScanSettingsBuilder(self.scan_settings)
        builder.with_min_snippet_lines(None)

        # file_snippet.min_snippet_lines = 5
        self.assertEqual(builder.min_snippet_lines, 5)

    # =========================================================================
    # Test with_honour_file_exts
    # =========================================================================

    def test_with_honour_file_exts_cli_true(self):
        """Test with_honour_file_exts with CLI 'true'."""
        builder = ScanSettingsBuilder(None)
        builder.with_honour_file_exts('true')

        self.assertTrue(builder.honour_file_exts)

    def test_with_honour_file_exts_cli_false(self):
        """Test with_honour_file_exts with CLI 'false'."""
        builder = ScanSettingsBuilder(None)
        builder.with_honour_file_exts('false')

        self.assertFalse(builder.honour_file_exts)

    def test_with_honour_file_exts_from_settings(self):
        """Test with_honour_file_exts from settings."""
        builder = ScanSettingsBuilder(self.scan_settings)
        builder.with_honour_file_exts(None)

        # file_snippet.honour_file_exts = true
        self.assertTrue(builder.honour_file_exts)

    def test_with_honour_file_exts_settings_overrides_cli(self):
        """Test with_honour_file_exts settings overrides CLI."""
        builder = ScanSettingsBuilder(self.scan_settings)
        builder.with_honour_file_exts('false')

        # file_snippet.honour_file_exts = true takes priority
        self.assertTrue(builder.honour_file_exts)

    # =========================================================================
    # Test with_ranking
    # =========================================================================

    def test_with_ranking_cli_true(self):
        """Test with_ranking with CLI 'true'."""
        builder = ScanSettingsBuilder(None)
        builder.with_ranking('true')

        self.assertTrue(builder.ranking)

    def test_with_ranking_cli_false(self):
        """Test with_ranking with CLI 'false'."""
        builder = ScanSettingsBuilder(None)
        builder.with_ranking('false')

        self.assertFalse(builder.ranking)

    def test_with_ranking_from_settings(self):
        """Test with_ranking from settings."""
        builder = ScanSettingsBuilder(self.scan_settings)
        builder.with_ranking(None)

        # file_snippet.ranking_enabled = true
        self.assertTrue(builder.ranking)

    # =========================================================================
    # Test with_ranking_threshold
    # =========================================================================

    def test_with_ranking_threshold_cli_only(self):
        """Test with_ranking_threshold uses CLI value."""
        builder = ScanSettingsBuilder(None)
        builder.with_ranking_threshold(50)

        self.assertEqual(builder.ranking_threshold, 50)

    def test_with_ranking_threshold_from_settings(self):
        """Test with_ranking_threshold from settings."""
        builder = ScanSettingsBuilder(self.scan_settings)
        builder.with_ranking_threshold(None)

        # file_snippet.ranking_threshold = 75
        self.assertEqual(builder.ranking_threshold, 75)

    # =========================================================================
    # Test method chaining
    # =========================================================================

    def test_method_chaining(self):
        """Test that all with_* methods support chaining."""
        builder = ScanSettingsBuilder(None)

        result = (builder
            .with_proxy('http://proxy:8080')
            .with_url('https://api.example.com')
            .with_ignore_cert_errors(True)
            .with_min_snippet_hits(5)
            .with_min_snippet_lines(3)
            .with_honour_file_exts('true')
            .with_ranking('true')
            .with_ranking_threshold(50))

        self.assertEqual(result, builder)
        self.assertEqual(builder.proxy, 'http://proxy:8080')
        self.assertEqual(builder.url, 'https://api.example.com')
        self.assertTrue(builder.ignore_cert_errors)
        self.assertEqual(builder.min_snippet_hits, 5)
        self.assertEqual(builder.min_snippet_lines, 3)
        self.assertTrue(builder.honour_file_exts)
        self.assertTrue(builder.ranking)
        self.assertEqual(builder.ranking_threshold, 50)


if __name__ == '__main__':
    unittest.main()