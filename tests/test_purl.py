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

from scanoss.utils.purl import versioned_purl


class VersionedPurlTests(unittest.TestCase):
    """
    Exercise versioned_purl
    """

    def test_pins_a_versionless_purl(self):
        self.assertEqual(
            versioned_purl('pkg:github/signalwire/freeswitch', 'v1.6.7'), 'pkg:github/signalwire/freeswitch@v1.6.7'
        )

    def test_keeps_an_encoded_namespace(self):
        self.assertEqual(versioned_purl('pkg:npm/%40electron/rebuild', '3.7.0'), 'pkg:npm/%40electron/rebuild@3.7.0')

    def test_keeps_a_purl_that_already_has_a_version(self):
        self.assertEqual(versioned_purl('pkg:npm/lodash@4.17.21', '4.17.21'), 'pkg:npm/lodash@4.17.21')

    def test_does_not_override_a_different_version_in_the_purl(self):
        self.assertEqual(versioned_purl('pkg:npm/lodash@4.17.21', '4.17.20'), 'pkg:npm/lodash@4.17.21')

    def test_keeps_the_purl_without_a_version(self):
        for version in (None, ''):
            with self.subTest(version=version):
                self.assertEqual(versioned_purl('pkg:npm/lodash', version), 'pkg:npm/lodash')

    def test_version_goes_before_qualifiers(self):
        self.assertEqual(
            versioned_purl('pkg:maven/org.acme/widgets?repository_url=repo.acme.org', '1.0'),
            'pkg:maven/org.acme/widgets@1.0?repository_url=repo.acme.org',
        )

    def test_at_sign_in_a_qualifier_is_not_a_version(self):
        self.assertEqual(
            versioned_purl('pkg:maven/org.acme/widgets?repository_url=user@repo.acme.org', '1.0'),
            'pkg:maven/org.acme/widgets@1.0?repository_url=user%40repo.acme.org',
        )

    def test_commit_hash_version(self):
        self.assertEqual(versioned_purl('pkg:github/scanoss/wfp', '6afc1f6'), 'pkg:github/scanoss/wfp@6afc1f6')

    def test_non_string_version_is_converted(self):
        self.assertEqual(versioned_purl('pkg:pypi/requests', 2), 'pkg:pypi/requests@2')

    def test_unparsable_purl_is_returned_unchanged(self):
        self.assertEqual(versioned_purl('not-a-purl', '1.0'), 'not-a-purl')


if __name__ == '__main__':
    unittest.main()
