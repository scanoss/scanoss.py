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
from unittest.mock import MagicMock

from scanoss.cyclonedx import CycloneDx
from scanoss.scanoss_settings import BomEntry
from scanoss.spdxlite import SpdxLite


def _make_scan_result(purl, component='test-comp', version='1.0.0'):
    """Create a minimal scan result entry (no acknowledgement — that comes from BOM rules)."""
    entry = {
        'id': 'file',
        'purl': [purl],
        'component': component,
        'version': version,
        'vendor': 'test-vendor',
        'url': f'https://github.com/test/{component}',
        'licenses': [{'name': 'MIT', 'source': 'component_declared'}],
    }
    return {'test/file.c': [entry]}


def _make_settings(bom_include=None, bom_replace=None, organization='SCANOSS'):
    """Create a mock ScanossSettings with BOM entries."""
    settings = MagicMock()
    settings.get_bom_include.return_value = bom_include or []
    settings.get_bom_replace.return_value = bom_replace or []
    settings.get_organization.return_value = organization
    return settings


class TestCycloneDxAnnotations(unittest.TestCase):
    """Test annotation building from BOM rules in CycloneDX output"""

    def test_cdx_annotation_from_bom_include(self):
        """CycloneDX should build annotation from matching BOM include rule"""
        data = _make_scan_result('pkg:npm/test@1.0.0')
        settings = _make_settings(bom_include=[
            BomEntry(purl='pkg:npm/test@1.0.0', acknowledgement='confirmed',
                     timestamp='2026-03-15T10:30:00Z'),
        ])
        cdx = CycloneDx(scanoss_settings=settings)
        success, output = cdx.produce_from_json(data)
        self.assertTrue(success)
        annotations = output.get('annotations', [])
        self.assertEqual(len(annotations), 1)
        self.assertEqual(annotations[0]['text'], 'confirmed')
        self.assertEqual(annotations[0]['timestamp'], '2026-03-15T10:30:00Z')
        self.assertEqual(annotations[0]['subjects'], ['pkg:npm/test@1.0.0'])
        self.assertEqual(annotations[0]['annotator']['organization']['name'], 'SCANOSS')

    def test_cdx_no_annotations_without_settings(self):
        """CycloneDX should not include annotations when no settings provided"""
        data = _make_scan_result('pkg:npm/test@1.0.0')
        cdx = CycloneDx()
        success, output = cdx.produce_from_json(data)
        self.assertTrue(success)
        self.assertNotIn('annotations', output)

    def test_cdx_no_annotations_when_no_matching_rule(self):
        """CycloneDX should not annotate components without matching BOM rules"""
        data = _make_scan_result('pkg:npm/test@1.0.0')
        settings = _make_settings(bom_include=[
            BomEntry(purl='pkg:npm/other@2.0.0', acknowledgement='confirmed'),
        ])
        cdx = CycloneDx(scanoss_settings=settings)
        success, output = cdx.produce_from_json(data)
        self.assertTrue(success)
        self.assertNotIn('annotations', output)

    def test_cdx_timestamp_fallback_to_current_time(self):
        """CycloneDX annotation should fall back to metadata timestamp when rule has no timestamp"""
        data = _make_scan_result('pkg:npm/test@1.0.0')
        settings = _make_settings(bom_include=[
            BomEntry(purl='pkg:npm/test@1.0.0', acknowledgement='confirmed'),
        ])
        cdx = CycloneDx(scanoss_settings=settings)
        success, output = cdx.produce_from_json(data)
        self.assertTrue(success)
        annotations = output.get('annotations', [])
        self.assertEqual(len(annotations), 1)
        self.assertEqual(annotations[0]['timestamp'], output['metadata']['timestamp'])

    def test_cdx_organization_from_settings(self):
        """CycloneDX annotation should use organization from settings"""
        data = _make_scan_result('pkg:npm/test@1.0.0')
        settings = _make_settings(
            bom_include=[BomEntry(purl='pkg:npm/test@1.0.0', acknowledgement='ack')],
            organization='MyOrg',
        )
        cdx = CycloneDx(scanoss_settings=settings)
        success, output = cdx.produce_from_json(data)
        self.assertTrue(success)
        annotations = output.get('annotations', [])
        self.assertEqual(annotations[0]['annotator']['organization']['name'], 'MyOrg')

    def test_cdx_no_component_properties(self):
        """CycloneDX components should NOT have properties for acknowledgement"""
        data = _make_scan_result('pkg:npm/test@1.0.0')
        settings = _make_settings(bom_include=[
            BomEntry(purl='pkg:npm/test@1.0.0', acknowledgement='confirmed'),
        ])
        cdx = CycloneDx(scanoss_settings=settings)
        success, output = cdx.produce_from_json(data)
        self.assertTrue(success)
        components = output.get('components', [])
        self.assertEqual(len(components), 1)
        self.assertNotIn('properties', components[0])

    def test_cdx_dependency_annotation(self):
        """CycloneDX should build annotation for dependency entries"""
        data = {
            'test/package.json': [{
                'id': 'dependency',
                'dependencies': [{
                    'purl': 'pkg:npm/dep@2.0.0',
                    'component': 'dep',
                    'version': '2.0.0',
                    'licenses': [{'name': 'Apache-2.0'}],
                }],
            }],
        }
        settings = _make_settings(bom_include=[
            BomEntry(purl='pkg:npm/dep@2.0.0', acknowledgement='noticed',
                     timestamp='2026-03-15T10:30:00Z'),
        ])
        cdx = CycloneDx(scanoss_settings=settings)
        success, output = cdx.produce_from_json(data)
        self.assertTrue(success)
        annotations = output.get('annotations', [])
        self.assertEqual(len(annotations), 1)
        self.assertEqual(annotations[0]['text'], 'noticed')
        self.assertEqual(annotations[0]['subjects'], ['pkg:npm/dep@2.0.0'])

    def test_cdx_replace_rule_annotation(self):
        """CycloneDX should build annotation from matching BOM replace rule"""
        data = _make_scan_result('pkg:npm/test@1.0.0')
        settings = _make_settings(bom_replace=[
            BomEntry(purl='pkg:npm/test@1.0.0', acknowledgement='replaced and verified',
                     timestamp='2026-03-15T10:30:00Z'),
        ])
        cdx = CycloneDx(scanoss_settings=settings)
        success, output = cdx.produce_from_json(data)
        self.assertTrue(success)
        annotations = output.get('annotations', [])
        self.assertEqual(len(annotations), 1)
        self.assertEqual(annotations[0]['text'], 'replaced and verified')


class TestSpdxLiteAnnotations(unittest.TestCase):
    """Test annotation building from BOM rules in SPDX output"""

    def _produce_spdx(self, data, settings=None):
        """Helper to produce SPDX output and return parsed JSON."""
        spdx = SpdxLite(scanoss_settings=settings)
        temp_dir = tempfile.gettempdir()
        output_file = os.path.join(temp_dir, f'test_spdx_{id(self)}.json')
        try:
            success = spdx.produce_from_json(data, output_file)
            self.assertTrue(success)
            with open(output_file, 'r') as f:
                return json.load(f)
        finally:
            if os.path.exists(output_file):
                os.remove(output_file)

    def test_spdx_annotation_from_bom_include(self):
        """SPDX should build annotation from matching BOM include rule"""
        data = _make_scan_result('pkg:npm/test@1.0.0')
        settings = _make_settings(bom_include=[
            BomEntry(purl='pkg:npm/test@1.0.0', acknowledgement='confirmed',
                     timestamp='2026-03-15T10:30:00Z'),
        ])
        output = self._produce_spdx(data, settings)
        annotations = output.get('annotations', [])
        self.assertEqual(len(annotations), 1)
        self.assertEqual(annotations[0]['comment'], 'confirmed')
        self.assertEqual(annotations[0]['annotationDate'], '2026-03-15T10:30:00Z')
        self.assertEqual(annotations[0]['annotationType'], 'REVIEW')
        self.assertEqual(annotations[0]['annotator'], 'Organization: SCANOSS')

    def test_spdx_no_annotations_without_settings(self):
        """SPDX should not include annotations when no settings provided"""
        data = _make_scan_result('pkg:npm/test@1.0.0')
        output = self._produce_spdx(data)
        self.assertNotIn('annotations', output)

    def test_spdx_timestamp_fallback(self):
        """SPDX annotation should fall back to creation date when rule has no timestamp"""
        data = _make_scan_result('pkg:npm/test@1.0.0')
        settings = _make_settings(bom_include=[
            BomEntry(purl='pkg:npm/test@1.0.0', acknowledgement='confirmed'),
        ])
        output = self._produce_spdx(data, settings)
        annotations = output.get('annotations', [])
        self.assertEqual(len(annotations), 1)
        self.assertEqual(annotations[0]['annotationDate'], output['creationInfo']['created'])

    def test_spdx_organization_from_settings(self):
        """SPDX annotation should use organization from settings"""
        data = _make_scan_result('pkg:npm/test@1.0.0')
        settings = _make_settings(
            bom_include=[BomEntry(purl='pkg:npm/test@1.0.0', acknowledgement='ack')],
            organization='MyOrg',
        )
        output = self._produce_spdx(data, settings)
        annotations = output.get('annotations', [])
        self.assertEqual(annotations[0]['annotator'], 'Organization: MyOrg')

    def test_spdx_no_package_comment(self):
        """SPDX packages should NOT have comment for acknowledgement"""
        data = _make_scan_result('pkg:npm/test@1.0.0')
        settings = _make_settings(bom_include=[
            BomEntry(purl='pkg:npm/test@1.0.0', acknowledgement='confirmed'),
        ])
        output = self._produce_spdx(data, settings)
        packages = output.get('packages', [])
        self.assertEqual(len(packages), 1)
        self.assertNotIn('comment', packages[0])

    def test_spdx_dependency_annotation(self):
        """SPDX should build annotation for dependency entries"""
        data = {
            'test/package.json': [{
                'id': 'dependency',
                'dependencies': [{
                    'purl': 'pkg:npm/dep@2.0.0',
                    'component': 'dep',
                    'version': '2.0.0',
                    'url': 'https://github.com/test/dep',
                    'licenses': [{'name': 'MIT'}],
                }],
            }],
        }
        settings = _make_settings(bom_include=[
            BomEntry(purl='pkg:npm/dep@2.0.0', acknowledgement='noticed',
                     timestamp='2026-03-15T10:30:00Z'),
        ])
        output = self._produce_spdx(data, settings)
        annotations = output.get('annotations', [])
        self.assertEqual(len(annotations), 1)
        self.assertEqual(annotations[0]['comment'], 'noticed')


if __name__ == '__main__':
    unittest.main()
