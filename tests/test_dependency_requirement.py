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

import os
import unittest

from scanoss.scancodedeps import REQUIREMENT_NAME_PREFIX_RE, ScancodeDeps

TEST_DIR = os.path.dirname(os.path.abspath(__file__))


def _sanitize(rq):
    return REQUIREMENT_NAME_PREFIX_RE.sub('', rq)


class TestSanitizeRequirement(unittest.TestCase):
    """Test the regex that strips package names from requirements"""

    def test_pip_exact_version(self):
        """pip exact match: strip name, keep '=='"""
        self.assertEqual(_sanitize('gtest==1.17.0'), '==1.17.0')

    def test_pip_less_equal(self):
        self.assertEqual(_sanitize('boost<=1.83.0'), '<=1.83.0')

    def test_pip_greater_equal(self):
        self.assertEqual(_sanitize('requests>=2.25.1'), '>=2.25.1')

    def test_pip_range(self):
        self.assertEqual(_sanitize('requests>=2.25.1,<3'), '>=2.25.1,<3')

    def test_pip_not_equal(self):
        self.assertEqual(_sanitize('foo!=1.0'), '!=1.0')

    def test_npm_caret_unchanged(self):
        """npm ^: no operator after name, unchanged"""
        self.assertEqual(_sanitize('^4.18.0'), '^4.18.0')

    def test_npm_tilde_unchanged(self):
        self.assertEqual(_sanitize('~4.18.0'), '~4.18.0')

    def test_npm_greater_equal(self):
        self.assertEqual(_sanitize('>=1.0.0'), '>=1.0.0')

    def test_bare_version_unchanged(self):
        """Plain version number with no operator: unchanged"""
        self.assertEqual(_sanitize('1.17.0'), '1.17.0')

    def test_name_prefix_of_another_package(self):
        """'requests-toolbelt>=1.0' strips full name, not partial"""
        self.assertEqual(_sanitize('requests-toolbelt>=1.0'), '>=1.0')


if __name__ == '__main__':
    unittest.main()
