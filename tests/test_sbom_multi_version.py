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

import json
import os
import tempfile
import unittest

from scanoss.cyclonedx import CycloneDx
from scanoss.spdxlite import SpdxLite

PURL = 'pkg:github/signalwire/freeswitch'


def _file_match(version, vulnerabilities=None):
    return [
        {
            'id': 'file',
            'component': 'freeswitch',
            'vendor': 'signalwire',
            'version': version,
            'latest': 'v1.10.12',
            'url': 'https://github.com/signalwire/freeswitch',
            'url_hash': 'abc123',
            'purl': [PURL],
            'licenses': [{'name': 'MPL-1.1', 'source': 'component_declared'}],
            'vulnerabilities': vulnerabilities or [],
        }
    ]


def _dependency(version):
    return [
        {
            'id': 'dependency',
            'dependencies': [{'purl': 'pkg:npm/lodash', 'component': 'lodash', 'version': version, 'licenses': []}],
        }
    ]


RAW = {
    'src/a.c': _file_match('v1.6.8', [{'ID': 'CVE-2024-0001', 'CVE': 'CVE-2024-0001', 'source': 'nvd'}]),
    'src/b.c': _file_match('v1.6.7', [{'ID': 'CVE-2024-0002', 'CVE': 'CVE-2024-0002', 'source': 'nvd'}]),
    'src/c.c': _file_match('v1.6.7'),
    'web/package.json': _dependency('4.17.21'),
    'tools/package.json': _dependency('4.17.20'),
}


class CycloneDxMultiVersionTests(unittest.TestCase):
    """
    Every detected version of a component is its own CycloneDX component.
    """

    def setUp(self):
        self.cdx = CycloneDx(debug=False)
        success, self.bom = self.cdx.produce_from_json(RAW, print_output=False)
        self.assertTrue(success)

    def test_one_component_per_version(self):
        versions = sorted(c['version'] for c in self.bom['components'] if c['purl'] == PURL)
        self.assertEqual(versions, ['v1.6.7', 'v1.6.8'])
        deps = sorted(c['version'] for c in self.bom['components'] if c['purl'] == 'pkg:npm/lodash')
        self.assertEqual(deps, ['4.17.20', '4.17.21'])

    def test_bom_refs_are_unique(self):
        refs = [c['bom-ref'] for c in self.bom['components']]
        self.assertEqual(len(refs), len(set(refs)))
        self.assertIn(f'{PURL}@v1.6.7', refs)

    def test_vulnerabilities_reference_their_own_version(self):
        affects = {v['id']: [a['ref'] for a in v['affects']] for v in self.bom['vulnerabilities']}
        self.assertEqual(affects['CVE-2024-0001'], [f'{PURL}@v1.6.8'])
        self.assertEqual(affects['CVE-2024-0002'], [f'{PURL}@v1.6.7'])

    def test_output_is_valid_cyclonedx(self):
        self.assertTrue(self.cdx.is_cyclonedx_json(json.dumps(self.bom)))

    def test_purls_request_keeps_each_version(self):
        request = self.cdx.get_purls_request_from_cdx(self.bom)
        self.assertIn({'purl': PURL, 'requirement': 'v1.6.7'}, request['purls'])
        self.assertIn({'purl': PURL, 'requirement': 'v1.6.8'}, request['purls'])


class SpdxLiteMultiVersionTests(unittest.TestCase):
    """
    Every detected version of a component is its own SPDX package.
    """

    def setUp(self):
        fd, out_path = tempfile.mkstemp(prefix='spdxlite_multi_', suffix='.json')
        os.close(fd)  # SpdxLite re-opens the path itself for writing
        try:
            self.assertTrue(SpdxLite(debug=False, output_file=out_path).produce_from_json(RAW))
            with open(out_path, 'r') as f:
                self.doc = json.load(f)
        finally:
            os.remove(out_path)

    def test_one_package_per_version(self):
        versions = sorted(p['versionInfo'] for p in self.doc['packages'] if p['name'] == 'freeswitch')
        self.assertEqual(versions, ['v1.6.7', 'v1.6.8'])
        deps = sorted(p['versionInfo'] for p in self.doc['packages'] if p['name'] == 'lodash')
        self.assertEqual(deps, ['4.17.20', '4.17.21'])

    def test_spdx_ids_are_unique_and_described(self):
        ids = [p['SPDXID'] for p in self.doc['packages']]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(sorted(ids), sorted(self.doc['documentDescribes']))


class CrossFormatTests(unittest.TestCase):
    """
    CycloneDX and SPDX Lite pin purls the same way.
    """

    def test_both_formats_agree_on_edge_cases(self):
        raw = {
            'package.json': [
                {
                    'id': 'dependency',
                    'dependencies': [
                        {'purl': 'pkg:npm/lodash@4.17.21', 'component': 'lodash', 'version': '4.17.21', 'licenses': []},
                        {'purl': 'pkg:npm/left-pad', 'component': 'left-pad', 'version': None, 'licenses': []},
                    ],
                }
            ]
        }
        _, bom = CycloneDx(debug=False).produce_from_json(raw, print_output=False)
        fd, out_path = tempfile.mkstemp(prefix='spdxlite_pin_', suffix='.json')
        os.close(fd)  # SpdxLite re-opens the path itself for writing
        try:
            SpdxLite(debug=False, output_file=out_path).produce_from_json(raw)
            with open(out_path, 'r') as f:
                doc = json.load(f)
        finally:
            os.remove(out_path)
        spdx_purls = sorted(r['referenceLocator'] for p in doc['packages'] for r in p['externalRefs'])
        self.assertEqual(sorted(c['bom-ref'] for c in bom['components']), spdx_purls)
        self.assertEqual(spdx_purls, ['pkg:npm/left-pad', 'pkg:npm/lodash@4.17.21'])


if __name__ == '__main__':
    unittest.main()
