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

from scanoss.spdxlite import SpdxLite


class MyTestCase(unittest.TestCase):
    """
    Exercise the SpdxLite class
    """
    def testSpdxLite(self):
        temp_dir = tempfile.gettempdir()
        spdx_lite_output = os.path.join(temp_dir, "spdxlite.json")
        test_data_dir = os.path.dirname(os.path.abspath(__file__))
        file_name = 'result.json'
        input_file_name = os.path.join(test_data_dir, 'data', file_name)
        spdx_lite = SpdxLite(debug = False, output_file=spdx_lite_output)
        spdx_lite.produce_from_file(input_file_name)
        md5_length = 32
        # Read data using absolute path
        with open(spdx_lite_output, 'r') as f:
            parsed_data = json.load(f)
            spdx_version = parsed_data.get("spdxVersion")
            spdx_id = parsed_data.get("SPDXID")
            name = parsed_data.get("name")
            organization = parsed_data.get("creationInfo",{}).get('creators')[2]
            creation_info_comment = parsed_data.get("creationInfo", {}).get('comment')
            document_describes = parsed_data.get("documentDescribes")
            packages = parsed_data.get("packages")

            self.assertEqual(spdx_version, "SPDX-2.2")
            self.assertEqual(spdx_id, "SPDXRef-DOCUMENT")
            self.assertEqual(name, "SCANOSS-SBOM")
            self.assertEqual(organization, "Organization: SCANOSS")
            self.assertEqual(creation_info_comment, "SBOM Build information - SBOM Type: Build")
            self.assertEqual(len(document_describes), 6)
            self.assertEqual(len(packages), 6)

            for package in packages:
                for checksum in package.get("checksums", []):
                    self.assertEqual(checksum.get("algorithm"), "MD5") #Check all algorithms be MD5
                    self.assertEqual(len(checksum.get("checksumValue")), md5_length) #Check checksum length value be 32


        os.remove(spdx_lite_output) #Removes tmp spdxlite.json file


class SpdxLiteCpeTests(unittest.TestCase):
    """
    Exercise CPE extraction and SPDX externalRefs emission.
    """

    @staticmethod
    def _build_raw(vulnerabilities, purl='pkg:github/postgres/postgres'):
        return {
            'src/main.c': [{
                'id': 'file',
                'component': 'postgresql',
                'vendor': 'postgresql',
                'version': '17.0',
                'latest': '17.0',
                'url': 'https://www.postgresql.org',
                'url_hash': 'abc123',
                'download_url': 'https://example.com/pg.tar.gz',
                'purl': [purl],
                'licenses': [{'name': 'PostgreSQL', 'source': 'component_declared'}],
                'vulnerabilities': vulnerabilities,
            }]
        }

    def _run(self, raw):
        fd, out_path = tempfile.mkstemp(prefix='spdxlite_cpe_', suffix='.json')
        os.close(fd)  # SpdxLite re-opens the path itself for writing
        try:
            spdx = SpdxLite(debug=False, output_file=out_path)
            spdx.produce_from_json(raw)
            with open(out_path, 'r') as f:
                return json.load(f)
        finally:
            if os.path.exists(out_path):
                os.remove(out_path)

    def _security_refs(self, doc):
        refs = doc['packages'][0]['externalRefs']
        return [r for r in refs if r['referenceCategory'] == 'SECURITY']

    def test_cpe23_emits_cpe23Type(self):
        cpe = 'cpe:2.3:a:postgresql:postgresql:17.0:*:*:*:*:*:*:*'
        doc = self._run(self._build_raw([{'ID': cpe, 'source': 'nvd'}]))
        refs = self._security_refs(doc)
        self.assertEqual(len(refs), 1)
        self.assertEqual(refs[0]['referenceType'], 'cpe23Type')
        self.assertEqual(refs[0]['referenceLocator'], cpe)

    def test_legacy_cpe22_slash_emits_cpe22Type(self):
        cpe = 'cpe:/a:postgresql:postgresql:17.0'
        doc = self._run(self._build_raw([{'ID': cpe, 'source': 'nvd'}]))
        refs = self._security_refs(doc)
        self.assertEqual(len(refs), 1)
        self.assertEqual(refs[0]['referenceType'], 'cpe22Type')
        self.assertEqual(refs[0]['referenceLocator'], cpe)

    def test_explicit_cpe22_prefix_emits_cpe22Type(self):
        cpe = 'cpe:2.2:a:postgresql:postgresql:17.0'
        doc = self._run(self._build_raw([{'ID': cpe, 'source': 'nvd'}]))
        refs = self._security_refs(doc)
        self.assertEqual(len(refs), 1)
        self.assertEqual(refs[0]['referenceType'], 'cpe22Type')

    def test_case_insensitive_prefix_detection(self):
        cpe = 'CPE:2.3:a:postgresql:postgresql:17.0:*:*:*:*:*:*:*'
        doc = self._run(self._build_raw([{'ID': cpe, 'source': 'nvd'}]))
        refs = self._security_refs(doc)
        self.assertEqual(len(refs), 1)
        self.assertEqual(refs[0]['referenceType'], 'cpe23Type')
        self.assertEqual(refs[0]['referenceLocator'], cpe)  # casing preserved in locator

    def test_duplicate_cpes_are_deduplicated(self):
        cpe = 'cpe:2.3:a:postgresql:postgresql:17.0:*:*:*:*:*:*:*'
        doc = self._run(self._build_raw([
            {'ID': cpe, 'source': 'nvd'},
            {'ID': cpe, 'source': 'nvd'},
            {'ID': cpe, 'source': 'nvd'},
        ]))
        refs = self._security_refs(doc)
        self.assertEqual(len(refs), 1)

    def test_dedup_is_case_insensitive_and_preserves_first_locator(self):
        lower = 'cpe:2.3:a:postgresql:postgresql:17.0:*:*:*:*:*:*:*'
        upper = 'CPE:2.3:A:POSTGRESQL:POSTGRESQL:17.0:*:*:*:*:*:*:*'
        doc = self._run(self._build_raw([
            {'ID': lower, 'source': 'nvd'},
            {'ID': upper, 'source': 'nvd'},
        ]))
        refs = self._security_refs(doc)
        self.assertEqual(len(refs), 1)
        self.assertEqual(refs[0]['referenceLocator'], lower)  # first-seen wins

    def test_cve_entries_are_ignored(self):
        doc = self._run(self._build_raw([
            {'ID': 'CVE-2024-12345', 'CVE': 'CVE-2024-12345',
             'source': 'nvd', 'severity': 'high'},
            {'ID': 'GHSA-xxxx-yyyy-zzzz', 'source': 'github'},
        ]))
        refs = self._security_refs(doc)
        self.assertEqual(refs, [])

    def test_mixed_cpe_versions_in_same_component(self):
        cpe23 = 'cpe:2.3:a:postgresql:postgresql:17.0:*:*:*:*:*:*:*'
        cpe22 = 'cpe:/a:postgresql:postgresql:17.0'
        doc = self._run(self._build_raw([
            {'ID': cpe23, 'source': 'nvd'},
            {'ID': cpe22, 'source': 'nvd'},
        ]))
        refs = self._security_refs(doc)
        self.assertEqual(len(refs), 2)
        types = {r['referenceType']: r['referenceLocator'] for r in refs}
        self.assertEqual(types['cpe23Type'], cpe23)
        self.assertEqual(types['cpe22Type'], cpe22)

    def test_unknown_cpe_format_falls_back_to_cpe23Type(self):
        odd_cpe = 'cpe:weird-format:postgresql:17.0'
        doc = self._run(self._build_raw([{'ID': odd_cpe, 'source': 'nvd'}]))
        refs = self._security_refs(doc)
        self.assertEqual(len(refs), 1)
        self.assertEqual(refs[0]['referenceType'], 'cpe23Type')
        self.assertEqual(refs[0]['referenceLocator'], odd_cpe)

    def test_no_vulnerabilities_field_produces_no_security_refs(self):
        raw = self._build_raw([])
        # Drop the key entirely to simulate entries without a vulnerabilities block
        del raw['src/main.c'][0]['vulnerabilities']
        doc = self._run(raw)
        self.assertEqual(self._security_refs(doc), [])
        # PURL externalRef must still be present
        refs = doc['packages'][0]['externalRefs']
        self.assertEqual(len(refs), 1)
        self.assertEqual(refs[0]['referenceType'], 'purl')

    def test_empty_vulnerabilities_list_produces_no_security_refs(self):
        doc = self._run(self._build_raw([]))
        self.assertEqual(self._security_refs(doc), [])

    def test_dependency_entries_do_not_emit_cpes(self):
        raw = {
            'package.json': [{
                'id': 'dependency',
                'dependencies': [{
                    'purl': 'pkg:npm/left-pad',
                    'component': 'left-pad',
                    'version': '1.3.0',
                    'url': 'https://npmjs.com/package/left-pad',
                    'licenses': [{'name': 'MIT', 'source': 'component_declared'}],
                }]
            }]
        }
        doc = self._run(raw)
        self.assertEqual(self._security_refs(doc), [])

    def test_lowercase_id_key_is_also_supported(self):
        cpe = 'cpe:2.3:a:postgresql:postgresql:17.0:*:*:*:*:*:*:*'
        # Raw scan output has been known to use 'id' (lowercase) occasionally
        doc = self._run(self._build_raw([{'id': cpe, 'source': 'nvd'}]))
        refs = self._security_refs(doc)
        self.assertEqual(len(refs), 1)
        self.assertEqual(refs[0]['referenceType'], 'cpe23Type')