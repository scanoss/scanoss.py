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

    @patch('platform.system')
    def test_unix_wfp_excludes_fh2(self, mock_platform):
        """Test that WFP does not include fh2 hash when running on Unix systems."""
        # Mock Unix environment
        mock_platform.return_value = 'Linux'
        winnowing = Winnowing(debug=True)

        filename = 'test-file.c'
        content = b'int main() {\n    return 0;\n}\n'

        wfp = winnowing.wfp_for_contents(filename, False, content)

        print(f'Unix WFP output:\n{wfp}')

        # Check that WFP does not contain fh2 line
        self.assertNotIn('fh2=', wfp)

    def test_cross_platform_compatibility(self):
        """Test that the same content produces consistent results across platforms."""
        filename = 'test-file.c'
        content = b'#include <stdio.h>\nint main() {\n    printf("Hello World\\n");\n    return 0;\n}\n'

        # Test with mocked Windows
        with patch('platform.system', return_value='Windows'):
            winnowing_windows = Winnowing(debug=True)
            wfp_windows = winnowing_windows.wfp_for_contents(filename, False, content)

        # Test with mocked Linux
        with patch('platform.system', return_value='Linux'):
            winnowing_linux = Winnowing(debug=True)
            wfp_linux = winnowing_linux.wfp_for_contents(filename, False, content)

        print(f'Windows WFP:\n{wfp_windows}')
        print(f'Linux WFP:\n{wfp_linux}')

        # Both should have file line with same MD5 (original content)
        windows_lines = wfp_windows.split('\n')
        linux_lines = wfp_linux.split('\n')

        windows_file_line = [line for line in windows_lines if line.startswith('file=')][0]
        linux_file_line = [line for line in linux_lines if line.startswith('file=')][0]

        # File lines should be identical (same original content MD5)
        self.assertEqual(windows_file_line, linux_file_line)

        # Windows should have additional fh2 line
        self.assertIn('fh2=', wfp_windows)
        self.assertNotIn('fh2=', wfp_linux)

        # Extract snippets (everything after file/fh2 lines)
        windows_snippets = [line for line in windows_lines if '=' in line and not line.startswith('file=') and not line.startswith('fh2=')]
        linux_snippets = [line for line in linux_lines if '=' in line and not line.startswith('file=')]

        # Snippet fingerprints should be identical across platforms
        self.assertEqual(windows_snippets, linux_snippets)

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

    def test_mixed_line_endings_scenarios(self):
        """Test various mixed line ending scenarios."""
        filename = 'test-file.c'

        # Test 1: LF only on Windows (should generate fh2)
        with patch('platform.system', return_value='Windows'):
            winnowing = Winnowing(debug=True)
            content_lf = b'int main() {\n    return 0;\n}\n'
            wfp = winnowing.wfp_for_contents(filename, False, content_lf)
            self.assertIn('fh2=', wfp)
            print(f'LF on Windows - WFP includes fh2: ✓')

        # Test 2: CRLF only on Windows (should NOT generate fh2)
        with patch('platform.system', return_value='Windows'):
            winnowing = Winnowing(debug=True)
            content_crlf = b'int main() {\r\n    return 0;\r\n}\r\n'
            wfp = winnowing.wfp_for_contents(filename, False, content_crlf)
            self.assertNotIn('fh2=', wfp)
            print(f'CRLF on Windows - WFP excludes fh2: ✓')

        # Test 3: Mixed line endings on any OS (should generate fh2)
        with patch('platform.system', return_value='Linux'):
            winnowing = Winnowing(debug=True)
            content_mixed = b'int main() {\r\n    printf("hello");\n    return 0;\r\n}\n'
            wfp = winnowing.wfp_for_contents(filename, False, content_mixed)
            self.assertIn('fh2=', wfp)
            print(f'Mixed line endings on Linux - WFP includes fh2: ✓')

        # Test 4: CR only on Windows (should generate fh2)
        with patch('platform.system', return_value='Windows'):
            winnowing = Winnowing(debug=True)
            content_cr = b'int main() {\r    return 0;\r}\r'
            wfp = winnowing.wfp_for_contents(filename, False, content_cr)
            self.assertIn('fh2=', wfp)
            print(f'CR only on Windows - WFP includes fh2: ✓')

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
