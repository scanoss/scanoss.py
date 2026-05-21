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

import os
import shutil
import tempfile
import unittest

from scanoss.cli import load_files_from_file, process_req_headers


class TestLoadFilesFromFile(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def _write(self, content: str, filename: str = 'filelist.txt') -> str:
        path = os.path.join(self.test_dir, filename)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)
        return path

    def test_reads_paths(self):
        p = self._write('src/foo.py\nsrc/bar.py\n')
        self.assertEqual(load_files_from_file(p), ['src/foo.py', 'src/bar.py'])

    def test_strips_leading_and_trailing_whitespace(self):
        p = self._write('  src/foo.py  \n\tsrc/bar.py\t\n')
        self.assertEqual(load_files_from_file(p), ['src/foo.py', 'src/bar.py'])

    def test_skips_empty_lines(self):
        p = self._write('\nsrc/foo.py\n\nsrc/bar.py\n\n')
        self.assertEqual(load_files_from_file(p), ['src/foo.py', 'src/bar.py'])

    def test_skips_whitespace_only_lines(self):
        p = self._write('src/foo.py\n   \nsrc/bar.py\n')
        self.assertEqual(load_files_from_file(p), ['src/foo.py', 'src/bar.py'])

    def test_skips_comment_lines(self):
        p = self._write('# header comment\nsrc/foo.py\n# another comment\nsrc/bar.py\n')
        self.assertEqual(load_files_from_file(p), ['src/foo.py', 'src/bar.py'])

    def test_empty_file_returns_empty_list(self):
        p = self._write('')
        self.assertEqual(load_files_from_file(p), [])

    def test_only_comments_and_blanks_returns_empty_list(self):
        p = self._write('# comment\n\n# another\n   \n')
        self.assertEqual(load_files_from_file(p), [])

    def test_nonexistent_file_returns_empty_list(self):
        self.assertEqual(load_files_from_file('/nonexistent/path/filelist.txt'), [])

    def test_none_filepath_returns_empty_list(self):
        self.assertEqual(load_files_from_file(None), [])  # type: ignore[arg-type]

    def test_empty_string_filepath_returns_empty_list(self):
        self.assertEqual(load_files_from_file(''), [])

    def test_windows_line_endings(self):
        # Write raw CRLF bytes to simulate a file produced on Windows
        path = os.path.join(self.test_dir, 'crlf.txt')
        with open(path, 'wb') as f:
            f.write(b'src/foo.py\r\nsrc/bar.py\r\n')
        self.assertEqual(load_files_from_file(path), ['src/foo.py', 'src/bar.py'])

    def test_utf8_paths(self):
        p = self._write('src/föö.py\nsrc/bàr.py\n')
        self.assertEqual(load_files_from_file(p), ['src/föö.py', 'src/bàr.py'])


class MyTestCase(unittest.TestCase):

    def test_header_argument_processor(self):
        # Test input
        headers_input = [
            'x-api-key:12334',
            'generic-header-1:generic-header-value-1',
            ' space-header : value-space-header',
            'generic-header2 generic-header-value-2'  # Note: missing colon separator
        ]

        # Process headers
        processed_headers = process_req_headers(headers_input)

        # Expected results (as a dictionary for easier comparison)
        expected_headers = {
            'x-api-key': '12334',
            'generic-header-1': 'generic-header-value-1',
            'space-header': 'value-space-header'
            # Note: generic-header2 not included as it doesn't have a colon separator
        }

        # Test exact dictionary equality
        self.assertEqual(processed_headers, expected_headers,
                         f"Headers don't match expected values.\nGot:"
                         f" {processed_headers}\nExpected: {expected_headers}")

        # Additional tests for specific cases
        self.assertIn('x-api-key', processed_headers, "Required header 'x-api-key' missing")
        self.assertEqual(
            processed_headers['x-api-key'],
            '12334',
            "Header value for 'x-api-key' is incorrect")

        # Test that the malformed header was not included
        self.assertNotIn('generic-header2', processed_headers,
                         "Malformed header without colon separator should not be included")