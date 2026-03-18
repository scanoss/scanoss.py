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
import tempfile
import unittest
from pathlib import Path

from scanoss.scanoss_settings import ScanossSettings
from scanoss.scanpostprocessor import ScanPostProcessor


class MyTestCase(unittest.TestCase):
    """
    Unit test cases for Scan Post-Processing
    """

    script_dir = os.path.dirname(os.path.abspath(__file__))
    scan_settings_path = Path(script_dir, 'data', 'scanoss.json').resolve()
    scan_settings = ScanossSettings(filepath=scan_settings_path)
    post_processor = ScanPostProcessor(scan_settings)

    result_json_path = Path(script_dir, 'data', 'result.json').resolve()

    def _load_result_data(self):
        """Load result.json fixture, returning a fresh dict each time."""
        with open(self.result_json_path) as f:
            return json.load(f)

    def _make_processor(self, settings_data):
        """Create a ScanPostProcessor from inline settings data, returns (processor, path)."""
        f = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
        json.dump(settings_data, f)
        f.close()
        settings = ScanossSettings(filepath=Path(f.name))
        return ScanPostProcessor(settings), f.name

    def test_remove_files(self):
        """
        Should remove component if matches path and purl
        """

        results = {
            'scanoss_settings.py': [
                {
                    'purl': ['pkg:github/scanoss/scanoss.py'],
                }
            ],
        }
        processed_results = self.post_processor.load_results(results).post_process()

        self.assertEqual(len(processed_results), 0)
        self.assertEqual(processed_results, {})

    def test_remove_files_no_results(self):
        """
        Should return empty dictionary when empty results are provided
        """
        processed_results = self.post_processor.load_results({}).post_process()

        self.assertEqual(len(processed_results), 0)
        self.assertEqual(processed_results, {})

    def test_remove_files_purl_match(self):
        """
        Should remove component if matches purl
        """
        results = {
            'no_matching_path.go': [
                {
                    'purl': ['matching/purl'],
                }
            ],
        }
        processed_results = self.post_processor.load_results(results).post_process()
        self.assertEqual(len(processed_results), 0)
        self.assertEqual(processed_results, {})

    def test_replace_purls_full_match(self):
        """
        Should replace purl if full match
        """
        results = {
            'full_match_test.py': [
                {
                    'purl': ['pkg:github/scanoss/full_match_test.py'],
                }
            ],
        }
        processed_results = self.post_processor.load_results(results).post_process()
        self.assertEqual(len(processed_results), 1)
        self.assertEqual(
            processed_results['full_match_test.py'][0]['purl'], ['pkg:github/scanoss/full_match_replaced.py']
        )

    def test_replace_purls_purl_match(self):
        """Should replace purl if matches purl"""
        results = {
            'only_purl_match.py': [
                {
                    'purl': ['pkg:github/scanoss/only_purl_match.py'],
                }
            ],
        }
        processed_results = self.post_processor.load_results(results).post_process()
        self.assertEqual(len(processed_results), 1)
        self.assertEqual(
            processed_results['only_purl_match.py'][0]['purl'], ['pkg:github/scanoss/only_purl_match_replaced.py']
        )


    def test_replace_purls_with_license(self):
        """Should apply the license from the replace rule to the result"""
        processor, path = self._make_processor({
            'bom': {
                'replace': [{
                    'purl': 'pkg:github/scanoss/scanner.c',
                    'replace_with': 'pkg:github/scanoss/replacement',
                    'license': 'Apache-2.0',
                }]
            }
        })
        try:
            processed = processor.load_results(self._load_result_data()).post_process()

            entry = processed['inc/json.h'][0]
            self.assertEqual(entry['purl'], ['pkg:github/scanoss/replacement'])
            self.assertEqual(entry['licenses'], [{'name': 'Apache-2.0'}])
        finally:
            os.unlink(path)

    def test_replace_purls_without_license(self):
        """When replace_with PURL is NOT in scan results and the rule has no
        license override, licenses should be removed entirely — we have no
        license info for the unknown replacement component."""
        processor, path = self._make_processor({
            'bom': {
                'replace': [{
                    'purl': 'pkg:github/scanoss/scanner.c',
                    'replace_with': 'pkg:github/scanoss/replacement',
                }]
            }
        })
        try:
            processed = processor.load_results(self._load_result_data()).post_process()

            entry = processed['inc/json.h'][0]
            self.assertEqual(entry['purl'], ['pkg:github/scanoss/replacement'])
            # 'replacement' is not in scan results, so there's no license info
            # to copy — the original component's licenses must be stripped
            self.assertNotIn('licenses', entry)
        finally:
            os.unlink(path)

    def test_replace_with_realistic_result(self):
        """Should replace a full realistic scan result and strip old metadata"""
        processor, path = self._make_processor({
            'bom': {
                'replace': [{
                    'purl': 'pkg:github/scanoss/scanner.c',
                    'replace_with': 'pkg:github/scanoss/replacement',
                    'license': 'GPL-2.0-only',
                }]
            }
        })
        try:
            processed = processor.load_results(self._load_result_data()).post_process()

            entry = processed['inc/json.h'][0]
            self.assertEqual(entry['purl'], ['pkg:github/scanoss/replacement'])
            self.assertEqual(entry['component'], 'replacement')
            self.assertEqual(entry['vendor'], 'scanoss')
            self.assertEqual(entry['status'], 'identified')
            self.assertEqual(entry['licenses'], [{'name': 'GPL-2.0-only'}])
            # source_hash belongs to the local scanned file and must be preserved
            self.assertIn('source_hash', entry)
            # Old component/KB metadata should be stripped
            for field in ('file', 'file_hash', 'file_url', 'latest', 'release_date',
                          'url_hash', 'url_stats', 'version', 'cryptography',
                          'vulnerabilities', 'provenance', 'dependencies', 'health',
                          'quality'):
                self.assertNotIn(field, entry)
        finally:
            os.unlink(path)

    def test_replace_with_existing_purl_preserves_per_file_fields(self):
        """When replace_with target exists in scan results (component_info_map),
        per-file fields must be preserved and component-level fields copied."""
        processor, path = self._make_processor({
            'bom': {
                'replace': [{
                    'purl': 'pkg:github/scanoss/scanner.c',
                    'replace_with': 'pkg:github/scanoss/engine',
                }]
            }
        })
        try:
            processed = processor.load_results(self._load_result_data()).post_process()

            entry = processed['inc/json.h'][0]
            self.assertEqual(entry['purl'], ['pkg:github/scanoss/engine'])
            self.assertEqual(entry['status'], 'identified')
            # Per-file fields must be from the ORIGINAL result (inc/json.h), not
            # from the component_info_map entry (which came from a different file)
            self.assertEqual(entry['file'], 'scanner.c-1.3.3/external/inc/json.h')
            self.assertEqual(entry['file_hash'], 'e91a03b850651dd56dd979ba92668a19')
            self.assertEqual(entry['source_hash'], 'e91a03b850651dd56dd979ba92668a19')
            self.assertEqual(entry['lines'], 'all')
            self.assertEqual(entry['matched'], '100%')
            self.assertEqual(entry['oss_lines'], 'all')
            # Component-level fields should come from the engine entry
            self.assertEqual(entry['component'], 'engine')
            self.assertEqual(entry['vendor'], 'scanoss')
            # Without a license override, the component's licenses are kept
            self.assertIn('licenses', entry)
            self.assertTrue(len(entry['licenses']) > 0)
        finally:
            os.unlink(path)

    def test_replace_with_existing_purl_empty_licenses_clears_original(self):
        """When replace_with PURL exists in scan results but has an empty
        licenses list, the original component's licenses must be replaced
        with the empty list — not left stale."""
        processor, path = self._make_processor({
            'bom': {
                'replace': [{
                    'purl': 'pkg:github/scanoss/scanner.c',
                    'replace_with': 'pkg:github/scanoss/jenkins-pipeline-example',
                }]
            }
        })
        try:
            processed = processor.load_results(self._load_result_data()).post_process()

            # inc/json.h originally had BSD-2-Clause + GPL-2.0-only licenses;
            # jenkins-pipeline-example (from inc/log.c) has licenses: []
            entry = processed['inc/json.h'][0]
            self.assertEqual(entry['purl'], ['pkg:github/scanoss/jenkins-pipeline-example'])
            # Original licenses must NOT remain — replaced with empty list
            self.assertEqual(entry['licenses'], [])
        finally:
            os.unlink(path)

    def test_replace_path_scoped_with_existing_purl_and_license_override(self):
        """Reproduce Sean's bug: path-scoped replace rule where replace_with PURL
        already exists in results from a different file. Per-file fields must be
        preserved, license override must be applied, and files outside the path
        must not be affected."""
        processor, path = self._make_processor({
            'bom': {
                'replace': [{
                    'path': 'src/',
                    'purl': 'pkg:github/scanoss/scanner.c',
                    'replace_with': 'pkg:github/scanoss/engine',
                    'license': 'GPL-3.0-only',
                }]
            }
        })
        try:
            processed = processor.load_results(self._load_result_data()).post_process()

            # src/json.c is under src/ and matches scanner.c → should be replaced
            entry = processed['src/json.c'][0]
            self.assertEqual(entry['purl'], ['pkg:github/scanoss/engine'])
            self.assertEqual(entry['status'], 'identified')
            self.assertEqual(entry['licenses'], [{'name': 'GPL-3.0-only'}])
            # Per-file fields must be from src/json.c, not from the engine entry
            self.assertEqual(entry['file'], 'scanner.c-1.3.3/external/src/json.c')
            self.assertEqual(entry['file_hash'], '8e4d433c1547b59681379e9fe9960546')
            self.assertEqual(entry['source_hash'], '8e4d433c1547b59681379e9fe9960546')
            # Component-level fields from engine
            self.assertEqual(entry['component'], 'engine')
            self.assertEqual(entry['vendor'], 'scanoss')

            # inc/json.h is NOT under src/ → should remain unchanged
            inc_entry = processed['inc/json.h'][0]
            self.assertEqual(inc_entry['purl'], ['pkg:github/scanoss/scanner.c'])
            self.assertEqual(inc_entry['status'], 'pending')
        finally:
            os.unlink(path)

    def test_replace_purl_with_version_no_match_unversioned_result(self):
        """Should NOT replace when rule has purl@version but result has no version"""
        processor, path = self._make_processor({
            'bom': {
                'replace': [{
                    'purl': 'pkg:github/scanoss/scanner.c@1.3.3',
                    'replace_with': 'pkg:github/scanoss/replacement@2.0.0',
                }]
            }
        })
        try:
            processed = processor.load_results(self._load_result_data()).post_process()

            entry = processed['inc/json.h'][0]
            # Should remain unchanged — result purl has no version
            self.assertEqual(entry['purl'], ['pkg:github/scanoss/scanner.c'])
            self.assertEqual(entry['status'], 'pending')
        finally:
            os.unlink(path)


if __name__ == '__main__':
    unittest.main()
