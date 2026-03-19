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

import json
import os
import tempfile
import unittest

from scanoss.cyclonedx import CycloneDx
from scanoss.spdxlite import SpdxLite


def _make_scan_result(purl, component='test-comp', version='1.0.0', acknowledgement=None):
    """Create a minimal scan result entry."""
    entry = {
        'id': 'file',
        'purl': [purl],
        'component': component,
        'version': version,
        'vendor': 'test-vendor',
        'url': f'https://github.com/test/{component}',
        'licenses': [{'name': 'MIT', 'source': 'component_declared'}],
    }
    if acknowledgement:
        entry['acknowledgement'] = acknowledgement
    return {'test/file.c': [entry]}


class TestCycloneDxAcknowledgement(unittest.TestCase):
    """Test acknowledgement propagation in CycloneDX output"""

    def test_cdx_includes_acknowledgement_property(self):
        """CycloneDX output should include scanoss:acknowledgement in component properties"""
        data = _make_scan_result('pkg:npm/test@1.0.0', acknowledgement='acknowledged')
        cdx = CycloneDx()
        success, output = cdx.produce_from_json(data)
        self.assertTrue(success)
        components = output.get('components', [])
        self.assertEqual(len(components), 1)
        props = components[0].get('properties', [])
        self.assertEqual(len(props), 1)
        self.assertEqual(props[0]['name'], 'scanoss:acknowledgement')
        self.assertEqual(props[0]['value'], 'acknowledged')

    def test_cdx_no_properties_when_no_acknowledgement(self):
        """CycloneDX output should not include properties when no acknowledgement"""
        data = _make_scan_result('pkg:npm/test@1.0.0')
        cdx = CycloneDx()
        success, output = cdx.produce_from_json(data)
        self.assertTrue(success)
        components = output.get('components', [])
        self.assertEqual(len(components), 1)
        self.assertNotIn('properties', components[0])

    def test_cdx_dependency_acknowledgement(self):
        """CycloneDX output should include acknowledgement for dependency entries"""
        data = {
            'test/package.json': [{
                'id': 'dependency',
                'dependencies': [{
                    'purl': 'pkg:npm/dep@2.0.0',
                    'component': 'dep',
                    'version': '2.0.0',
                    'licenses': [{'name': 'Apache-2.0'}],
                    'acknowledgement': 'noticed',
                }],
            }],
        }
        cdx = CycloneDx()
        success, output = cdx.produce_from_json(data)
        self.assertTrue(success)
        components = output.get('components', [])
        self.assertEqual(len(components), 1)
        props = components[0].get('properties', [])
        self.assertEqual(len(props), 1)
        self.assertEqual(props[0]['name'], 'scanoss:acknowledgement')
        self.assertEqual(props[0]['value'], 'noticed')


class TestSpdxLiteAcknowledgement(unittest.TestCase):
    """Test acknowledgement propagation in SPDX output"""

    def test_spdx_includes_comment_when_acknowledgement(self):
        """SPDX output should include comment on package when acknowledgement present"""
        data = _make_scan_result('pkg:npm/test@1.0.0', acknowledgement='acknowledged')
        spdx = SpdxLite()
        temp_dir = tempfile.gettempdir()
        output_file = os.path.join(temp_dir, 'test_ack_spdx.json')
        try:
            success = spdx.produce_from_json(data, output_file)
            self.assertTrue(success)
            with open(output_file, 'r') as f:
                output = json.load(f)
            packages = output.get('packages', [])
            self.assertEqual(len(packages), 1)
            self.assertEqual(packages[0].get('comment'), 'acknowledged')
        finally:
            if os.path.exists(output_file):
                os.remove(output_file)

    def test_spdx_no_comment_when_no_acknowledgement(self):
        """SPDX output should not include comment when no acknowledgement"""
        data = _make_scan_result('pkg:npm/test@1.0.0')
        spdx = SpdxLite()
        temp_dir = tempfile.gettempdir()
        output_file = os.path.join(temp_dir, 'test_no_ack_spdx.json')
        try:
            success = spdx.produce_from_json(data, output_file)
            self.assertTrue(success)
            with open(output_file, 'r') as f:
                output = json.load(f)
            packages = output.get('packages', [])
            self.assertEqual(len(packages), 1)
            self.assertNotIn('comment', packages[0])
        finally:
            if os.path.exists(output_file):
                os.remove(output_file)

    def test_spdx_dependency_acknowledgement(self):
        """SPDX output should include comment for dependency entries with acknowledgement"""
        data = {
            'test/package.json': [{
                'id': 'dependency',
                'dependencies': [{
                    'purl': 'pkg:npm/dep@2.0.0',
                    'component': 'dep',
                    'version': '2.0.0',
                    'url': 'https://github.com/test/dep',
                    'licenses': [{'name': 'MIT'}],
                    'acknowledgement': 'noticed',
                }],
            }],
        }
        spdx = SpdxLite()
        temp_dir = tempfile.gettempdir()
        output_file = os.path.join(temp_dir, 'test_dep_ack_spdx.json')
        try:
            success = spdx.produce_from_json(data, output_file)
            self.assertTrue(success)
            with open(output_file, 'r') as f:
                output = json.load(f)
            packages = output.get('packages', [])
            self.assertEqual(len(packages), 1)
            self.assertEqual(packages[0].get('comment'), 'noticed')
        finally:
            if os.path.exists(output_file):
                os.remove(output_file)


if __name__ == '__main__':
    unittest.main()
