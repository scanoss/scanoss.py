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
import shutil
import tempfile
import unittest

from scanoss.scanner import Scanner


class TestIterWfpFiles(unittest.TestCase):
    """Tests for Scanner._iter_wfp_files() static method."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp_dir)

    def _create_wfp_file(self, content: str) -> str:
        path = os.path.join(self.tmp_dir, 'test.wfp')
        with open(path, 'w') as f:
            f.write(content)
        return path

    def test_single_file_entry(self):
        wfp_content = (
            'file=abc123,100,src/main.c\n'
            '4=abcdef\n'
            '8=012345\n'
        )
        wfp_file = self._create_wfp_file(wfp_content)
        results = list(Scanner._iter_wfp_files(wfp_file))
        self.assertEqual(len(results), 1)
        file_path, content = results[0]
        self.assertEqual(file_path, 'src/main.c')
        self.assertEqual(content, wfp_content)

    def test_multiple_file_entries(self):
        wfp_content = (
            'file=aaa,10,src/a.c\n'
            '4=111111\n'
            'file=bbb,20,src/b.c\n'
            '4=222222\n'
            'file=ccc,30,src/c.c\n'
            '4=333333\n'
        )
        wfp_file = self._create_wfp_file(wfp_content)
        results = list(Scanner._iter_wfp_files(wfp_file))
        self.assertEqual(len(results), 3)
        self.assertEqual(results[0][0], 'src/a.c')
        self.assertEqual(results[1][0], 'src/b.c')
        self.assertEqual(results[2][0], 'src/c.c')

    def test_content_preserved_exactly(self):
        wfp_content = (
            'file=aaa,10,src/a.c\n'
            '4=111111\n'
            '8=aaaaaa\n'
            'file=bbb,20,src/b.c\n'
            '4=222222\n'
        )
        wfp_file = self._create_wfp_file(wfp_content)
        results = list(Scanner._iter_wfp_files(wfp_file))
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0][1], 'file=aaa,10,src/a.c\n4=111111\n8=aaaaaa\n')
        self.assertEqual(results[1][1], 'file=bbb,20,src/b.c\n4=222222\n')

    def test_empty_file(self):
        wfp_file = self._create_wfp_file('')
        results = list(Scanner._iter_wfp_files(wfp_file))
        self.assertEqual(results, [])

    def test_file_entry_without_snippets(self):
        wfp_content = 'file=abc123,100,src/only_header.c\n'
        wfp_file = self._create_wfp_file(wfp_content)
        results = list(Scanner._iter_wfp_files(wfp_file))
        self.assertEqual(len(results), 1)
        file_path, content = results[0]
        self.assertEqual(file_path, 'src/only_header.c')
        self.assertEqual(content, 'file=abc123,100,src/only_header.c\n')

    def test_consecutive_file_entries(self):
        wfp_content = (
            'file=aaa,10,src/a.c\n'
            'file=bbb,20,src/b.c\n'
            'file=ccc,30,src/c.c\n'
        )
        wfp_file = self._create_wfp_file(wfp_content)
        results = list(Scanner._iter_wfp_files(wfp_file))
        self.assertEqual(len(results), 3)
        self.assertEqual(results[0][0], 'src/a.c')
        self.assertEqual(results[0][1], 'file=aaa,10,src/a.c\n')
        self.assertEqual(results[1][0], 'src/b.c')
        self.assertEqual(results[1][1], 'file=bbb,20,src/b.c\n')
        self.assertEqual(results[2][0], 'src/c.c')
        self.assertEqual(results[2][1], 'file=ccc,30,src/c.c\n')


if __name__ == '__main__':
    unittest.main()
