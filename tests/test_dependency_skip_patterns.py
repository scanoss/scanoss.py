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

import unittest

from scanoss.scancodedeps import ScancodeDeps
from scanoss.scanoss_settings import ScanossSettings


SAMPLE_DEPS = {
    'files': [
        {'file': 'package.json', 'purls': [{'purl': 'pkg:npm/express@4.18.0'}]},
        {'file': 'vendor/package.json', 'purls': [{'purl': 'pkg:npm/lodash@4.17.21'}]},
        {'file': 'vendor/sub/package.json', 'purls': [{'purl': 'pkg:npm/axios@1.0.0'}]},
        {'file': 'third_party/lib/requirements.txt', 'purls': [{'purl': 'pkg:pypi/requests@2.28.0'}]},
        {'file': 'src/go.mod', 'purls': [{'purl': 'pkg:golang/github.com/gin-gonic/gin@1.9.0'}]},
    ]
}


def _make_settings(patterns):
    """Helper to create a ScanossSettings with dependency skip patterns."""
    settings = ScanossSettings(debug=True)
    settings.data = {
        'settings': {
            'skip': {
                'patterns': {
                    'dependencies': patterns,
                }
            }
        }
    }
    return settings


def _make_sc_deps(scanoss_settings=None):
    """Helper to create a ScancodeDeps with optional settings."""
    return ScancodeDeps(debug=True, scanoss_settings=scanoss_settings)



class TestDependencySkipPatterns(unittest.TestCase):
    """Tests for dependency skip patterns filtering on ScancodeDeps."""

    def test_no_settings_no_filtering(self):
        """No settings -> deps returned unchanged."""
        sc = _make_sc_deps(scanoss_settings=None)
        result = sc.filter_dependencies_by_path(SAMPLE_DEPS)
        self.assertEqual(result, SAMPLE_DEPS)

    def test_empty_patterns_no_filtering(self):
        """Empty patterns list -> deps returned unchanged."""
        settings = _make_settings([])
        sc = _make_sc_deps(scanoss_settings=settings)
        result = sc.filter_dependencies_by_path(SAMPLE_DEPS)
        self.assertEqual(result, SAMPLE_DEPS)

    def test_exact_path_match(self):
        """Exact path match -> that file is skipped."""
        settings = _make_settings(['vendor/package.json'])
        sc = _make_sc_deps(scanoss_settings=settings)
        result = sc.filter_dependencies_by_path(SAMPLE_DEPS)
        files = result['files']
        matched_paths = [f['file'] for f in files]
        self.assertNotIn('vendor/package.json', matched_paths)
        self.assertIn('package.json', matched_paths)
        self.assertIn('src/go.mod', matched_paths)

    def test_glob_pattern_vendor(self):
        """Glob pattern vendor/** -> all files under vendor/ skipped."""
        settings = _make_settings(['vendor/**'])
        sc = _make_sc_deps(scanoss_settings=settings)
        result = sc.filter_dependencies_by_path(SAMPLE_DEPS)
        files = result['files']
        matched_paths = [f['file'] for f in files]
        self.assertNotIn('vendor/package.json', matched_paths)
        self.assertNotIn('vendor/sub/package.json', matched_paths)
        self.assertIn('package.json', matched_paths)
        self.assertIn('third_party/lib/requirements.txt', matched_paths)
        self.assertIn('src/go.mod', matched_paths)

    def test_directory_pattern(self):
        """Directory pattern third_party/ -> files under it skipped."""
        settings = _make_settings(['third_party/'])
        sc = _make_sc_deps(scanoss_settings=settings)
        result = sc.filter_dependencies_by_path(SAMPLE_DEPS)
        files = result['files']
        matched_paths = [f['file'] for f in files]
        self.assertNotIn('third_party/lib/requirements.txt', matched_paths)
        self.assertIn('package.json', matched_paths)
        self.assertIn('vendor/package.json', matched_paths)

    def test_multiple_patterns(self):
        """Multiple patterns -> all matching files skipped."""
        settings = _make_settings(['vendor/**', 'third_party/'])
        sc = _make_sc_deps(scanoss_settings=settings)
        result = sc.filter_dependencies_by_path(SAMPLE_DEPS)
        files = result['files']
        matched_paths = [f['file'] for f in files]
        self.assertNotIn('vendor/package.json', matched_paths)
        self.assertNotIn('vendor/sub/package.json', matched_paths)
        self.assertNotIn('third_party/lib/requirements.txt', matched_paths)
        self.assertIn('package.json', matched_paths)
        self.assertIn('src/go.mod', matched_paths)
        self.assertEqual(len(files), 2)

    def test_no_match_all_kept(self):
        """Pattern that matches nothing -> all files kept."""
        settings = _make_settings(['nonexistent/**'])
        sc = _make_sc_deps(scanoss_settings=settings)
        result = sc.filter_dependencies_by_path(SAMPLE_DEPS)
        self.assertEqual(len(result['files']), len(SAMPLE_DEPS['files']))


class TestGetSkipPatternsDependencies(unittest.TestCase):
    """Tests for ScanossSettings.get_skip_patterns('dependencies')."""

    def test_returns_correct_data(self):
        """get_skip_patterns('dependencies') returns the configured patterns."""
        settings = _make_settings(['vendor/**', 'third_party/'])
        result = settings.get_skip_patterns('dependencies')
        self.assertEqual(result, ['vendor/**', 'third_party/'])

    def test_returns_empty_when_key_missing(self):
        """get_skip_patterns('dependencies') returns [] when key is absent (backward compat)."""
        settings = ScanossSettings(debug=True)
        settings.data = {
            'settings': {
                'skip': {
                    'patterns': {
                        'scanning': ['*.log'],
                    }
                }
            }
        }
        result = settings.get_skip_patterns('dependencies')
        self.assertEqual(result, [])

    def test_returns_empty_when_no_settings(self):
        """get_skip_patterns('dependencies') returns [] with empty data."""
        settings = ScanossSettings(debug=True)
        settings.data = {}
        result = settings.get_skip_patterns('dependencies')
        self.assertEqual(result, [])


if __name__ == '__main__':
    unittest.main()
