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
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.
"""
import json
import os
import tempfile
import unittest

from scanoss.cyclonedx import CycloneDx
from scanoss.spdxlite import SpdxLite


def multi_version_raw(vuln_on_first: bool = True) -> dict:
    """
    Raw scan results where the same component is detected twice, at 1.3.3 and 2.0.0.
    Raw results carry versionless purls: the version lives in the entry's ``version`` field.
    """
    vuln = [{'ID': 'CVE-2024-9999', 'CVE': 'CVE-2024-9999', 'source': 'nvd', 'severity': 'high'}] if vuln_on_first else []
    return {
        'lib/old.c': [{
            'id': 'd3', 'purl': ['pkg:github/acme/widgets'], 'vendor': 'acme', 'component': 'widgets',
            'version': '1.3.3', 'url': 'https://acme.example/widgets', 'url_hash': 'a' * 32,
            'download_url': 'https://acme.example/widgets-1.3.3.tar.gz',
            'licenses': [{'name': 'MIT', 'source': 'file_header'}], 'vulnerabilities': vuln,
        }],
        'lib/new.c': [{
            'id': 'd3', 'purl': ['pkg:github/acme/widgets'], 'vendor': 'acme', 'component': 'widgets',
            'version': '2.0.0', 'url': 'https://acme.example/widgets', 'url_hash': 'b' * 32,
            'download_url': 'https://acme.example/widgets-2.0.0.tar.gz',
            'licenses': [{'name': 'MIT', 'source': 'file_header'}], 'vulnerabilities': [],
        }],
    }


class SpdxLiteVersionRetentionTests(unittest.TestCase):
    """
    SPDX Lite keeps every detected version of a component (issue: SBOM converters
    retained only the first version encountered during file processing).
    """

    def test_parse_keeps_both_versions_of_the_same_component(self):
        summary = SpdxLite(debug=False).parse(multi_version_raw())
        self.assertEqual(
            sorted(summary.keys()),
            ['pkg:github/acme/widgets@1.3.3', 'pkg:github/acme/widgets@2.0.0'],
        )
        self.assertEqual(sorted(c.get('version') for c in summary.values()), ['1.3.3', '2.0.0'])

    def test_document_lists_one_package_per_version(self):
        spdx = SpdxLite(debug=False)
        fd, out_path = tempfile.mkstemp(prefix='spdxlite_ver_', suffix='.json')
        os.close(fd)
        try:
            self.assertTrue(spdx.produce_from_json(multi_version_raw(), output_file=out_path))
            with open(out_path, 'r') as f:
                doc = json.load(f)
        finally:
            if os.path.exists(out_path):
                os.remove(out_path)
        self.assertEqual(len(doc['packages']), 2)
        versions = sorted(p['versionInfo'] for p in doc['packages'])
        self.assertEqual(versions, ['1.3.3', '2.0.0'])
        locators = sorted(
            r['referenceLocator']
            for p in doc['packages']
            for r in p['externalRefs']
            if r['referenceType'] == 'purl'
        )
        self.assertEqual(
            locators,
            ['pkg:github/acme/widgets@1.3.3', 'pkg:github/acme/widgets@2.0.0'],
        )
        # Distinct versions get distinct SPDX IDs.
        self.assertEqual(len({p['SPDXID'] for p in doc['packages']}), 2)
        self.assertEqual(len(doc['documentDescribes']), 2)

    def test_same_version_still_deduplicates(self):
        raw = {path: [dict(entry, version='1.3.3') for entry in entries]
               for path, entries in multi_version_raw().items()}
        summary = SpdxLite(debug=False).parse(raw)
        self.assertEqual(sorted(summary.keys()), ['pkg:github/acme/widgets@1.3.3'])

    def test_purl_with_its_own_version_is_left_alone(self):
        raw = {'lib/linux.c': [{
            'id': 'd3', 'purl': ['pkg:github/torvalds/linux@v5.13'], 'vendor': 'torvalds',
            'component': 'linux', 'version': 'v5.13', 'url': 'https://kernel.org', 'url_hash': 'c' * 32,
            'licenses': [{'name': 'GPL-2.0-only', 'source': 'file_header'}], 'vulnerabilities': [],
        }]}
        summary = SpdxLite(debug=False).parse(raw)
        self.assertEqual(sorted(summary.keys()), ['pkg:github/torvalds/linux@v5.13'])

    def test_missing_version_keeps_bare_purl_key(self):
        raw = {'lib/plain.c': [{
            'id': 'd3', 'purl': ['pkg:github/acme/plain'], 'vendor': 'acme', 'component': 'plain',
            'version': None, 'url': 'https://acme.example/plain', 'url_hash': 'd' * 32,
            'licenses': [], 'vulnerabilities': [],
        }]}
        summary = SpdxLite(debug=False).parse(raw)
        self.assertEqual(sorted(summary.keys()), ['pkg:github/acme/plain'])


class CycloneDxVersionRetentionTests(unittest.TestCase):
    """
    The CycloneDX converter keeps every detected version of a component, and its
    vulnerability ``affects`` refs point at the versioned components.
    """

    def test_parse_keeps_both_versions_of_the_same_component(self):
        cdx, vdx = CycloneDx(debug=False).parse(multi_version_raw())
        self.assertEqual(
            sorted(cdx.keys()),
            ['pkg:github/acme/widgets@1.3.3', 'pkg:github/acme/widgets@2.0.0'],
        )
        self.assertEqual(sorted(c.get('version') for c in cdx.values()), ['1.3.3', '2.0.0'])
        # The vulnerability was only reported on the 1.3.3 entry, so it affects that version.
        self.assertEqual(sorted(vdx['CVE-2024-9999']['affects']), ['pkg:github/acme/widgets@1.3.3'])

    def test_both_versions_listed_when_both_carry_the_vulnerability(self):
        raw = multi_version_raw()
        for entries in raw.values():
            entries[0]['vulnerabilities'] = [
                {'ID': 'CVE-2024-9999', 'CVE': 'CVE-2024-9999', 'source': 'nvd', 'severity': 'high'}]
        cdx, vdx = CycloneDx(debug=False).parse(raw)
        self.assertEqual(len(cdx), 2)
        self.assertEqual(
            sorted(vdx['CVE-2024-9999']['affects']),
            ['pkg:github/acme/widgets@1.3.3', 'pkg:github/acme/widgets@2.0.0'],
        )

    def test_same_version_still_deduplicates(self):
        raw = {path: [dict(entry, version='1.3.3') for entry in entries]
               for path, entries in multi_version_raw().items()}
        cdx, _ = CycloneDx(debug=False).parse(raw)
        self.assertEqual(sorted(cdx.keys()), ['pkg:github/acme/widgets@1.3.3'])


if __name__ == '__main__':
    unittest.main()
