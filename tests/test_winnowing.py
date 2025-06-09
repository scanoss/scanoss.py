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

import platform
import unittest
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
        has_crlf, has_lf, has_cr = winnowing._Winnowing__detect_line_endings(content_lf)
        self.assertFalse(has_crlf)
        self.assertTrue(has_lf)
        self.assertFalse(has_cr)

        # Test CRLF only
        content_crlf = b'line1\r\nline2\r\nline3\r\n'
        has_crlf, has_lf, has_cr = winnowing._Winnowing__detect_line_endings(content_crlf)
        self.assertTrue(has_crlf)
        self.assertFalse(has_lf)
        self.assertFalse(has_cr)

        # Test CR only (old Mac style)
        content_cr = b'line1\rline2\rline3\r'
        has_crlf, has_lf, has_cr = winnowing._Winnowing__detect_line_endings(content_cr)
        self.assertFalse(has_crlf)
        self.assertFalse(has_lf)
        self.assertTrue(has_cr)

        # Test mixed CRLF and LF
        content_mixed = b'line1\r\nline2\nline3\r\n'
        has_crlf, has_lf, has_cr = winnowing._Winnowing__detect_line_endings(content_mixed)
        self.assertTrue(has_crlf)
        self.assertTrue(has_lf)
        self.assertFalse(has_cr)

    def test_opposite_hash_logic(self):
        """Test the logic of opposite hash calculation."""
        winnowing = Winnowing(debug=True)

        # Test different line ending scenarios
        content_lf = b'line1\nline2\nline3\n'
        content_crlf = b'line1\r\nline2\r\nline3\r\n'
        content_cr = b'line1\rline2\rline3\r'
        content_mixed = b'line1\r\nline2\nline3\r'

        hash_lf = winnowing._Winnowing__calculate_opposite_line_ending_hash(content_lf)
        hash_crlf = winnowing._Winnowing__calculate_opposite_line_ending_hash(content_crlf)
        hash_cr = winnowing._Winnowing__calculate_opposite_line_ending_hash(content_cr)
        hash_mixed = winnowing._Winnowing__calculate_opposite_line_ending_hash(content_mixed)

        print(f'LF opposite hash: {hash_lf}')
        print(f'CRLF opposite hash: {hash_crlf}')
        print(f'CR opposite hash: {hash_cr}')
        print(f'Mixed opposite hash: {hash_mixed}')

        # LF, CR, and mixed content should all produce CRLF hash (same result)
        self.assertEqual(hash_lf, hash_cr)
        self.assertEqual(hash_lf, hash_mixed)

        # CRLF content should produce LF hash (different from the others)
        self.assertNotEqual(hash_crlf, hash_lf)

    @unittest.skipUnless(platform.system() == 'Windows', 'Windows-specific test')
    def test_actual_windows_behavior(self):
        """Test actual Windows behavior when running on Windows."""
        winnowing = Winnowing(debug=True)
        filename = 'test-file.c'
        content = b'int main() {\n    return 0;\n}\n'

        wfp = winnowing.wfp_for_contents(filename, False, content)

        print(f'Actual Windows WFP:\n{wfp}')

        # On actual Windows with LF content, should include fh2
        # Should always generate fh2 when line endings are present
        self.assertIn('fh2=', wfp)

    def test_empty_file_fh2(self):
        """Test fh2 behavior with empty files."""
        winnowing = Winnowing(debug=True)
        content = b''
        wfp = winnowing.wfp_for_contents('empty.txt', False, content)

        print(f'Empty file WFP:\n{wfp}')

        # Empty files should not generate fh2
        self.assertNotIn('fh2=', wfp)

    def test_no_line_endings_fh2(self):
        """Test files without any line endings."""
        winnowing = Winnowing(debug=True)
        content = b'no line endings here'
        wfp = winnowing.wfp_for_contents('noline.txt', False, content)

        print(f'No line endings WFP:\n{wfp}')

        # Files without line endings should not generate fh2
        self.assertNotIn('fh2=', wfp)

    def test_all_platforms_generate_fh2(self):
        """Test that all platforms generate fh2 when line endings are present."""
        winnowing = Winnowing(debug=True)
        content = b'line1\nline2\n'
        wfp = winnowing.wfp_for_contents('test.txt', False, content)

        print(f'Platform-independent WFP:\n{wfp}')

        # Any platform should generate fh2 when line endings are present
        self.assertIn('fh2=', wfp)

    def test_verify_opposite_hash_calculation(self):
        """Test that the opposite hash calculation works correctly."""
        winnowing = Winnowing(debug=True)

        # Test LF -> CRLF conversion
        content_lf = b'line1\nline2\nline3\n'
        wfp_lf = winnowing.wfp_for_contents('test_lf.txt', False, content_lf)

        # Test CRLF -> LF conversion
        content_crlf = b'line1\r\nline2\r\nline3\r\n'
        wfp_crlf = winnowing.wfp_for_contents('test_crlf.txt', False, content_crlf)

        print(f'LF content WFP:\n{wfp_lf}')
        print(f'CRLF content WFP:\n{wfp_crlf}')

        # Both should generate fh2
        self.assertIn('fh2=', wfp_lf)
        self.assertIn('fh2=', wfp_crlf)

        # Extract fh2 values
        lf_fh2 = wfp_lf.split('fh2=')[1].split('\n')[0]
        crlf_fh2 = wfp_crlf.split('fh2=')[1].split('\n')[0]

        # The fh2 values should be swapped (LF file gets CRLF hash, CRLF file gets LF hash)
        import hashlib
        expected_lf_to_crlf = hashlib.md5(content_lf.replace(b'\n', b'\r\n')).hexdigest()
        expected_crlf_to_lf = hashlib.md5(content_crlf.replace(b'\r\n', b'\n')).hexdigest()

        self.assertEqual(lf_fh2, expected_lf_to_crlf)
        self.assertEqual(crlf_fh2, expected_crlf_to_lf)

    def test_binary_file_with_line_endings(self):
        """Test binary files with embedded line endings."""
        winnowing = Winnowing(debug=True)
        # Binary content with embedded newlines
        content = b'\x00\x01\n\x02\x03\r\n\x04'
        wfp = winnowing.wfp_for_contents('binary.bin', True, content)

        print(f'Binary file WFP:\n{wfp}')

        # Binary files should not generate fh2
        self.assertNotIn('fh2=', wfp)

    def test_cr_only_line_endings(self):
        """Test classic Mac CR-only line endings."""
        winnowing = Winnowing(debug=True)
        content = b'line1\rline2\rline3\r'
        wfp = winnowing.wfp_for_contents('mac.txt', False, content)

        print(f'CR-only WFP:\n{wfp}')

        # Should generate fh2 (platform independent)
        self.assertIn('fh2=', wfp)

        # Should normalize CR to CRLF for the opposite hash
        import hashlib
        expected = content.replace(b'\r', b'\r\n')
        expected_hash = hashlib.md5(expected).hexdigest()
        self.assertIn(f'fh2={expected_hash}', wfp)

    def test_whitespace_only_file(self):
        """Test files with only whitespace characters."""
        winnowing = Winnowing(debug=True)
        content = b'   \n\t\n   \n'
        wfp = winnowing.wfp_for_contents('whitespace.txt', False, content)

        print(f'Whitespace-only WFP:\n{wfp}')

        # Should generate fh2 since it has line endings
        self.assertIn('fh2=', wfp)

    def test_mixed_complex_line_endings(self):
        """Test complex mixed line ending scenarios."""
        winnowing = Winnowing(debug=True)
        # Mix of CRLF, LF, and CR
        content = b'line1\r\nline2\nline3\rline4\r\nline5\n'
        wfp = winnowing.wfp_for_contents('mixed.txt', False, content)

        print(f'Mixed line endings WFP:\n{wfp}')

        # Should generate fh2
        self.assertIn('fh2=', wfp)

        # Verify the hash calculation
        import hashlib
        normalized = content.replace(b'\r\n', b'\n').replace(b'\r', b'\n')
        expected_crlf = normalized.replace(b'\n', b'\r\n')
        expected_hash = hashlib.md5(expected_crlf).hexdigest()
        self.assertIn(f'fh2={expected_hash}', wfp)

    def test_fh2_with_skip_snippets(self):
        """Test fh2 generation when skip_snippets is enabled."""
        winnowing = Winnowing(debug=True, skip_snippets=True)
        content = b'line1\nline2\nline3\n'
        wfp = winnowing.wfp_for_contents('test.txt', False, content)

        print(f'Skip snippets WFP:\n{wfp}')

        # Should still generate fh2 even when skipping snippets
        self.assertIn('fh2=', wfp)
        # But should not contain snippet fingerprints (line numbers)
        lines = wfp.split('\n')
        snippet_lines = [line for line in lines if '=' in line and line[0].isdigit()]
        self.assertEqual(len(snippet_lines), 0)

    def test_fh2_with_obfuscation(self):
        """Test fh2 generation with obfuscation enabled."""
        winnowing = Winnowing(debug=True, obfuscate=True)
        content = b'line1\nline2\nline3\n'
        wfp = winnowing.wfp_for_contents('test.txt', False, content)

        print(f'Obfuscated WFP:\n{wfp}')

        # Should still generate fh2 with obfuscation
        self.assertIn('fh2=', wfp)
        # Filename should be obfuscated
        self.assertIn('1.txt', wfp)
        self.assertNotIn('test.txt', wfp)

    def test_large_file_with_line_endings(self):
        """Test large files with many line endings."""
        winnowing = Winnowing(debug=True, size_limit=True, post_size=1)  # 1KB limit
        # Create content larger than the limit
        content = b'line\n' * 1000  # Should exceed 1KB
        wfp = winnowing.wfp_for_contents('large.txt', False, content)

        print(f'Large file WFP length: {len(wfp)}')

        # Should still generate fh2 even with size limits
        self.assertIn('fh2=', wfp)

    def test_single_line_no_newline(self):
        """Test single line files without trailing newline."""
        winnowing = Winnowing(debug=True)
        content = b'single line without newline'
        wfp = winnowing.wfp_for_contents('single.txt', False, content)

        print(f'Single line no newline WFP:\n{wfp}')

        # Should not generate fh2 (no line endings)
        self.assertNotIn('fh2=', wfp)

    def test_file_with_null_bytes_and_newlines(self):
        """Test files with null bytes mixed with newlines."""
        winnowing = Winnowing(debug=True)
        content = b'line1\x00\nline2\x00\x00\nline3\n'
        wfp = winnowing.wfp_for_contents('nullbytes.txt', False, content)

        print(f'Null bytes with newlines WFP:\n{wfp}')

        # Should generate fh2 (has line endings)
        self.assertIn('fh2=', wfp)


if __name__ == '__main__':
    unittest.main()
