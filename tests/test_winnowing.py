"""
SPDX-License-Identifier: MIT

  Copyright (c) 2021, SCANOSS

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
import platform
from unittest.mock import patch

from scanoss.winnowing import Winnowing


class MyTestCase(unittest.TestCase):
    """
    Exercise the Winnowing class
    """

    def test_winnowing(self):
        winnowing = Winnowing(debug=True)
        filename = 'test-file.c'
        contents = 'c code contents'
        content_types = bytes(contents, encoding='raw_unicode_escape')
        wfp = winnowing.wfp_for_contents(filename, False, content_types)
        print(f'WFP for {filename}: {wfp}')
        self.assertIsNotNone(wfp)
        filename = __file__
        wfp = winnowing.wfp_for_file(filename, filename)
        print(f'WFP for {filename}: {wfp}')
        self.assertIsNotNone(wfp)

    def test_snippet_skip(self):
        winnowing = Winnowing(debug=True)
        filename = 'test-file.jar'
        contents = 'jar file contents'
        content_types = bytes(contents, encoding='raw_unicode_escape')
        wfp = winnowing.wfp_for_contents(filename, False, content_types)
        print(f'WFP for {filename}: {wfp}')
        self.assertIsNotNone(wfp)

    def test_snippet_strip(self):
        winnowing = Winnowing(
            debug=True, hpsm=True, strip_snippet_ids=['d5e54c33,b03faabe'], strip_hpsm_ids=['0d2fffaffc62d18']
        )
        filename = 'test-file.py'
        with open(__file__, 'rb') as f:
            contents = f.read()
        print('--- Test snippet and HPSM strip ---')
        wfp = winnowing.wfp_for_contents(filename, False, contents)
        found = 0
        print(f'WFP for {filename}: {wfp}')
        try:
            found = wfp.index('d5e54c33,b03faabe')
        except ValueError:
            found = -1
        self.assertEqual(found, -1)

        try:
            found = wfp.index('0d2fffaffc62d18')
        except ValueError:
            found = -1
        self.assertEqual(found, -1)

    def test_windows_hash_calculation(self):
        """Test Windows-specific hash calculation with CRLF line endings."""
        import hashlib

        # Test content with LF line endings
        content_lf = b'line1\nline2\nline3\n'
        # Expected content with CRLF line endings for Windows hash
        content_crlf = b'line1\r\nline2\r\nline3\r\n'

        # Calculate the expected Windows hash manually
        expected_windows_hash = hashlib.md5(content_crlf).hexdigest()
        lf_hash = hashlib.md5(content_lf).hexdigest()

        print(f'LF content hash: {lf_hash}')
        print(f'CRLF content hash (Windows): {expected_windows_hash}')

        # They should be different
        self.assertNotEqual(lf_hash, expected_windows_hash)

    @patch('platform.system')
    def test_windows_wfp_includes_fh2(self, mock_platform):
        """Test that WFP includes fh2 hash when running on Windows."""
        # Mock Windows environment
        mock_platform.return_value = 'Windows'
        winnowing = Winnowing(debug=True)

        filename = 'test-file.c'
        content = b'int main() {\n    return 0;\n}\n'

        wfp = winnowing.wfp_for_contents(filename, False, content)

        print(f'Windows WFP output:\n{wfp}')

        # Check that WFP contains fh2 line
        self.assertIn('fh2=', wfp)

        # Extract the fh2 hash from WFP
        lines = wfp.split('\n')
        fh2_line = [line for line in lines if line.startswith('fh2=')]
        self.assertEqual(len(fh2_line), 1)

        fh2_hash = fh2_line[0].split('=')[1]

        # Verify it matches expected CRLF conversion
        import hashlib
        content_crlf = content.replace(b'\n', b'\r\n')
        expected_hash = hashlib.md5(content_crlf).hexdigest()
        self.assertEqual(fh2_hash, expected_hash)

    def test_line_ending_detection(self):
        """Test line ending detection logic."""
        winnowing = Winnowing(debug=True)

        # Test LF only
        content_lf = b'line1\nline2\nline3\n'
        has_crlf, has_lf, has_cr, has_mixed = winnowing.__detect_line_endings(content_lf)
        self.assertFalse(has_crlf)
        self.assertTrue(has_lf)
        self.assertFalse(has_cr)
        self.assertFalse(has_mixed)

        # Test CRLF only
        content_crlf = b'line1\r\nline2\r\nline3\r\n'
        has_crlf, has_lf, has_cr, has_mixed = winnowing.__detect_line_endings(content_crlf)
        self.assertTrue(has_crlf)
        self.assertFalse(has_lf)
        self.assertFalse(has_cr)
        self.assertFalse(has_mixed)

        # Test CR only (old Mac style)
        content_cr = b'line1\rline2\rline3\r'
        has_crlf, has_lf, has_cr, has_mixed = winnowing.__detect_line_endings(content_cr)
        self.assertFalse(has_crlf)
        self.assertFalse(has_lf)
        self.assertTrue(has_cr)
        self.assertFalse(has_mixed)

        # Test mixed CRLF and LF
        content_mixed = b'line1\r\nline2\nline3\r\n'
        has_crlf, has_lf, has_cr, has_mixed = winnowing.__detect_line_endings(content_mixed)
        self.assertTrue(has_crlf)
        self.assertTrue(has_lf)
        self.assertFalse(has_cr)
        self.assertTrue(has_mixed)

    def test_windows_hash_normalization(self):
        """Test that Windows hash properly normalizes different line endings."""
        winnowing = Winnowing(debug=True)

        # All these should produce the same Windows hash after normalization
        content_lf = b'line1\nline2\nline3\n'
        content_crlf = b'line1\r\nline2\r\nline3\r\n'
        content_cr = b'line1\rline2\rline3\r'
        content_mixed = b'line1\r\nline2\nline3\r'

        hash_lf = winnowing.__calculate_opposite_line_ending_hash(content_lf)
        hash_crlf = winnowing.__calculate_opposite_line_ending_hash(content_crlf)
        hash_cr = winnowing.__calculate_opposite_line_ending_hash(content_cr)
        hash_mixed = winnowing.__calculate_opposite_line_ending_hash(content_mixed)

        print(f'LF hash: {hash_lf}')
        print(f'CRLF hash: {hash_crlf}')
        print(f'CR hash: {hash_cr}')
        print(f'Mixed hash: {hash_mixed}')

        # All should be equal after normalization
        self.assertEqual(hash_lf, hash_crlf)
        self.assertEqual(hash_lf, hash_cr)
        self.assertEqual(hash_lf, hash_mixed)

    @unittest.skipUnless(platform.system() == 'Windows', 'Windows-specific test')
    def test_actual_windows_behavior(self):
        """Test actual Windows behavior when running on Windows."""
        winnowing = Winnowing(debug=True)
        filename = 'test-file.c'
        content = b'int main() {\n    return 0;\n}\n'

        wfp = winnowing.wfp_for_contents(filename, False, content)

        print(f'Actual Windows WFP:\n{wfp}')

        # On actual Windows with LF content, should include fh2
        if platform.system() == 'Windows':
            self.assertIn('fh2=', wfp)


if __name__ == '__main__':
    unittest.main()
