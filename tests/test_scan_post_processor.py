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

import os
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


class TestAcknowledgementInjection(unittest.TestCase):
    """Unit tests for acknowledgement injection during post-processing"""

    def _make_settings(self, settings_data: dict) -> ScanossSettings:
        settings = ScanossSettings()
        settings.data = settings_data
        return settings

    def test_replace_injects_acknowledgement(self):
        """Replace rule with acknowledgement should inject it into the result"""
        settings = self._make_settings({
            'bom': {
                'replace': [{
                    'purl': 'pkg:npm/old-lib',
                    'replace_with': 'pkg:npm/new-lib',
                    'acknowledgement': 'acknowledged',
                }],
            }
        })
        results = {
            'src/main.c': [{'purl': ['pkg:npm/old-lib']}],
        }
        processor = ScanPostProcessor(settings)
        processed = processor.load_results(results).post_process()
        self.assertEqual(processed['src/main.c'][0]['acknowledgement'], 'acknowledged')

    def test_replace_no_acknowledgement_when_absent(self):
        """Replace rule without acknowledgement should not add it to the result"""
        settings = self._make_settings({
            'bom': {
                'replace': [{
                    'purl': 'pkg:npm/old-lib',
                    'replace_with': 'pkg:npm/new-lib',
                }],
            }
        })
        results = {
            'src/main.c': [{'purl': ['pkg:npm/old-lib']}],
        }
        processor = ScanPostProcessor(settings)
        processed = processor.load_results(results).post_process()
        self.assertNotIn('acknowledgement', processed['src/main.c'][0])

    def test_include_injects_acknowledgement(self):
        """Include entry with acknowledgement should inject it into matching result"""
        settings = self._make_settings({
            'bom': {
                'include': [{
                    'purl': 'pkg:npm/vue',
                    'acknowledgement': 'noticed',
                }],
            }
        })
        results = {
            'src/main.c': [{'purl': ['pkg:npm/vue']}],
        }
        processor = ScanPostProcessor(settings)
        processed = processor.load_results(results).post_process()
        self.assertEqual(processed['src/main.c'][0]['acknowledgement'], 'noticed')

    def test_include_no_acknowledgement_when_absent(self):
        """Include entry without acknowledgement should not add it"""
        settings = self._make_settings({
            'bom': {
                'include': [{
                    'purl': 'pkg:npm/vue',
                }],
            }
        })
        results = {
            'src/main.c': [{'purl': ['pkg:npm/vue']}],
        }
        processor = ScanPostProcessor(settings)
        processed = processor.load_results(results).post_process()
        self.assertNotIn('acknowledgement', processed['src/main.c'][0])

    def test_replace_acknowledgement_takes_priority_over_include(self):
        """When both replace and include have acknowledgement, replace should win"""
        settings = self._make_settings({
            'bom': {
                'include': [{
                    'purl': 'pkg:npm/new-lib',
                    'acknowledgement': 'include-ack',
                }],
                'replace': [{
                    'purl': 'pkg:npm/old-lib',
                    'replace_with': 'pkg:npm/new-lib',
                    'acknowledgement': 'replace-ack',
                }],
            }
        })
        results = {
            'src/main.c': [{'purl': ['pkg:npm/old-lib']}],
        }
        processor = ScanPostProcessor(settings)
        processed = processor.load_results(results).post_process()
        self.assertEqual(processed['src/main.c'][0]['acknowledgement'], 'replace-ack')

    def test_include_acknowledgement_with_path_scope(self):
        """Include acknowledgement should respect path scoping"""
        settings = self._make_settings({
            'bom': {
                'include': [{
                    'path': 'src/vendor/',
                    'purl': 'pkg:npm/vue',
                    'acknowledgement': 'noticed',
                }],
            }
        })
        results = {
            'src/vendor/lib.c': [{'purl': ['pkg:npm/vue']}],
            'src/main.c': [{'purl': ['pkg:npm/vue']}],
        }
        processor = ScanPostProcessor(settings)
        processed = processor.load_results(results).post_process()
        self.assertEqual(processed['src/vendor/lib.c'][0]['acknowledgement'], 'noticed')
        self.assertNotIn('acknowledgement', processed['src/main.c'][0])


if __name__ == '__main__':
    unittest.main()
