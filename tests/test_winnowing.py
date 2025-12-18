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

    def test_skip_headers_flag(self):
        """Test skip_headers flag functionality."""
        # Sample Python file with headers, imports, and implementation
        test_content = b"""# Copyright 2024 SCANOSS
# Licensed under MIT License
# All rights reserved

import os
import sys
import json
from pathlib import Path

def function1():
    data = {"key": "value"}
    return json.dumps(data)

def function2():
    path = Path("/tmp")
    return str(path)

class MyClass:
    def __init__(self):
        self.data = []

    def add_item(self, item):
        self.data.append(item)
"""

        # Test WITHOUT skip_headers
        winnowing_no_skip = Winnowing(debug=False, skip_headers=False)
        wfp_no_skip = winnowing_no_skip.wfp_for_contents('test.py', False, test_content)

        # Test WITH skip_headers
        winnowing_skip = Winnowing(debug=False, skip_headers=True)
        wfp_skip = winnowing_skip.wfp_for_contents('test.py', False, test_content)

        print(f'WFP without skip_headers:\n{wfp_no_skip}')
        print(f'\nWFP with skip_headers:\n{wfp_skip}')

        # Both should have file= line
        self.assertIn('file=', wfp_no_skip)
        self.assertIn('file=', wfp_skip)

        # Extract snippet line numbers from both WFPs
        def extract_line_numbers(wfp):
            lines = wfp.split('\n')
            line_numbers = []
            for line in lines:
                if '=' in line and line.split('=')[0].isdigit():
                    line_numbers.append(int(line.split('=')[0]))
            return line_numbers

        lines_no_skip = extract_line_numbers(wfp_no_skip)
        lines_skip = extract_line_numbers(wfp_skip)

        # Both should have snippet lines
        self.assertGreater(len(lines_no_skip), 0, "Should have snippets without skip_headers")
        self.assertGreater(len(lines_skip), 0, "Should have snippets with skip_headers")

        # First line number with skip_headers should be HIGHER (skipped headers/imports)
        # Line 10 in the content is "def function1():" which is where real code starts
        min_line_no_skip = min(lines_no_skip)
        min_line_skip = min(lines_skip)

        print(f'First snippet line without skip_headers: {min_line_no_skip}')
        print(f'First snippet line with skip_headers: {min_line_skip}')

        # With skip_headers, first line should be after imports (around line 10+)
        # Without skip_headers, first line should be earlier (around line 5-8)
        self.assertGreater(
            min_line_skip,
            min_line_no_skip,
            "skip_headers should result in higher starting line number"
        )

        # Verify line 10+ (implementation) appears in skip_headers output
        self.assertGreaterEqual(
            min_line_skip,
            10,
            "With skip_headers, snippets should start at implementation (line 10+)"
        )

        # Verify start_line tag is present in skip_headers output
        self.assertIn('start_line=', wfp_skip, "start_line tag should be present with skip_headers")
        self.assertNotIn('start_line=', wfp_no_skip, "start_line tag should NOT be present without skip_headers")

        # Extract and validate start_line value
        start_line_value = None
        for line in wfp_skip.split('\n'):
            if line.startswith('start_line='):
                start_line_value = int(line.split('=')[1])
                break

        self.assertIsNotNone(start_line_value, "start_line value should be found")
        self.assertGreater(start_line_value, 0, "start_line should indicate skipped lines")
        print(f'start_line tag value: {start_line_value}')

    def test_skip_headers_with_different_languages(self):
        """Test skip_headers with different programming languages."""

        # JavaScript test
        js_content = b"""/*
 * Copyright 2024
 * Licensed under MIT
 */

import React from 'react';
import { Component } from 'react';

class App extends Component {
    render() {
        return <div>Hello</div>;
    }
}
"""
        winnowing_js = Winnowing(debug=False, skip_headers=True)
        wfp_js = winnowing_js.wfp_for_contents('test.js', False, js_content)

        print(f'JavaScript WFP with skip_headers:\n{wfp_js}')

        # Should have snippets starting from class definition (not imports)
        self.assertIn('file=', wfp_js)

        # Go test
        go_content = b"""// Copyright 2024
// Licensed under MIT

package main

import (
    "fmt"
    "os"
)

func main() {
    fmt.Println("Hello")
}
"""
        winnowing_go = Winnowing(debug=False, skip_headers=True)
        wfp_go = winnowing_go.wfp_for_contents('test.go', False, go_content)

        print(f'Go WFP with skip_headers:\n{wfp_go}')

        # Should have snippets starting from func main (not package/imports)
        self.assertIn('file=', wfp_go)