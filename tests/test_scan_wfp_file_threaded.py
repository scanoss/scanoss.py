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
from typing import NamedTuple, Optional
from unittest.mock import MagicMock, patch

from scanoss.scanner import Scanner
from scanoss.scanoss_settings import SbomContext


class Batch(NamedTuple):
    wfp: str
    sbom: Optional[dict]


class TestScanWfpFileThreaded(unittest.TestCase):
    """Tests for Scanner.scan_wfp_file_threaded() batching logic."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp_dir)

    def _create_wfp_file(self, content: str) -> str:
        path = os.path.join(self.tmp_dir, 'test.wfp')
        with open(path, 'w') as f:
            f.write(content)
        return path

    def _make_scanner(self, **overrides):
        """Create a Scanner with __init__ bypassed and minimal attributes set."""
        with patch.object(Scanner, '__init__', lambda self: None):
            scanner = Scanner()
        scanner.scanoss_settings = None
        scanner.threaded_scan = MagicMock()
        scanner.max_post_size = 64 * 1024
        scanner.post_file_count = 32
        scanner.nb_threads = 5
        # Patch the private __run_scan_threaded to avoid thread infrastructure
        scanner._Scanner__run_scan_threaded = MagicMock(return_value=True)
        for key, value in overrides.items():
            setattr(scanner, key, value)
        return scanner

    def _get_batches(self, scanner):
        """Return list of Batch(wfp, sbom) from queue_add calls."""
        return [
            Batch(call.args[0], call.kwargs.get('sbom'))
            for call in scanner.threaded_scan.queue_add.call_args_list
        ]

    # ------------------------------------------------------------------
    # Test cases
    # ------------------------------------------------------------------

    def test_single_file_queued(self):
        """A single file entry produces one queue_add call with the WFP content."""
        wfp = 'file=abc123,100,src/main.c\n4=aaaabbbb\n'
        wfp_file = self._create_wfp_file(wfp)
        scanner = self._make_scanner()

        result = scanner.scan_wfp_file_threaded(wfp_file)

        self.assertTrue(result)
        batches = self._get_batches(scanner)
        self.assertEqual(len(batches), 1)
        self.assertEqual(batches[0].wfp, wfp)
        self.assertIsNone(batches[0].sbom)

    def test_multiple_files_single_batch(self):
        """Multiple small files that fit in one batch produce a single queue_add call."""
        wfp_lines = (
            'file=aaa,10,src/a.c\n4=11112222\n'
            'file=bbb,20,src/b.c\n4=33334444\n'
            'file=ccc,30,src/c.c\n4=55556666\n'
        )
        wfp_file = self._create_wfp_file(wfp_lines)
        scanner = self._make_scanner()

        scanner.scan_wfp_file_threaded(wfp_file)

        batches = self._get_batches(scanner)
        self.assertEqual(len(batches), 1)
        # The batch should contain all three file entries concatenated
        self.assertEqual(batches[0].wfp.count('file='), 3)

    def test_file_count_flush(self):
        """When post_file_count is exceeded the batch is flushed.

        The flush condition is ``wfp_file_count > post_file_count`` (checked
        *after* adding the current file).  With ``post_file_count=1``:
          - after file a: count=1, 1>1? no
          - after file b: count=2, 2>1? yes → flush [a, b]
          - after file c: count=1, 1>1? no  → flushed at end-of-loop [c]
        """
        wfp_lines = (
            'file=aaa,10,src/a.c\n4=11112222\n'
            'file=bbb,20,src/b.c\n4=33334444\n'
            'file=ccc,30,src/c.c\n4=55556666\n'
        )
        wfp_file = self._create_wfp_file(wfp_lines)
        scanner = self._make_scanner(post_file_count=1)

        scanner.scan_wfp_file_threaded(wfp_file)

        batches = self._get_batches(scanner)
        self.assertEqual(len(batches), 2)
        # First batch: files a and b (flushed when count reaches 2 > 1)
        self.assertEqual(batches[0].wfp.count('file='), 2)
        # Second batch: file c (flushed at end of loop)
        self.assertEqual(batches[1].wfp.count('file='), 1)

    def test_size_limit_flush(self):
        """When accumulated WFP size exceeds max_post_size the batch is flushed before adding."""
        file_a = 'file=aaa,10,src/a.c\n4=11112222\n'
        file_b = 'file=bbb,20,src/b.c\n4=33334444\n'
        wfp_lines = file_a + file_b
        wfp_file = self._create_wfp_file(wfp_lines)

        # Set max_post_size so file_a alone fits, but file_a + file_b would not.
        # The pre-add size check: (wfp_size + scan_size) >= max_post_size
        size_a = len(file_a.encode('utf-8'))
        size_b = len(file_b.encode('utf-8'))
        scanner = self._make_scanner(max_post_size=size_a + size_b - 1)

        scanner.scan_wfp_file_threaded(wfp_file)

        batches = self._get_batches(scanner)
        self.assertEqual(len(batches), 2)
        # First batch: file a (flushed because adding b would exceed limit)
        self.assertIn('src/a.c', batches[0].wfp)
        self.assertNotIn('src/b.c', batches[0].wfp)
        # Second batch: file b (flushed at end of loop)
        self.assertIn('src/b.c', batches[1].wfp)

    def test_empty_wfp_file(self):
        """An empty WFP file results in no queue_add calls."""
        wfp_file = self._create_wfp_file('')
        scanner = self._make_scanner()

        result = scanner.scan_wfp_file_threaded(wfp_file)

        self.assertTrue(result)
        scanner.threaded_scan.queue_add.assert_not_called()

    def test_returns_true_on_success(self):
        """Method returns True when __run_scan_threaded returns True."""
        wfp = 'file=abc123,100,src/main.c\n4=aaaabbbb\n'
        wfp_file = self._create_wfp_file(wfp)
        scanner = self._make_scanner()

        result = scanner.scan_wfp_file_threaded(wfp_file)

        self.assertTrue(result)
        scanner._Scanner__run_scan_threaded.assert_called_once()


if __name__ == '__main__':
    unittest.main()
