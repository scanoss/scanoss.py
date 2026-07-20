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
import subprocess
import sys
import tempfile
import unittest


class TestScanWfpExitCode(unittest.TestCase):
    """Regression tests for `scan --wfp` exit-code handling (SP-4512).

    The `--wfp` branch used to discard the scanner's success/failure status,
    so a failed scan still exited 0 — inconsistent with the folder, STDIN and
    dependency scan modes, which all exit non-zero on failure.
    """

    # An unreachable endpoint: 127.0.0.1 with a port nothing listens on, so the
    # scan fails fast with a connection error instead of hitting the network.
    UNREACHABLE_APIURL = 'http://127.0.0.1:1/api/scan/direct'

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.wfp_file = os.path.join(self.tmp_dir, 'test.wfp')
        with open(self.wfp_file, 'w', encoding='utf-8') as f:
            f.write('file=abc123,100,src/main.c\n4=aaaabbbb\n')
        self.output_file = os.path.join(self.tmp_dir, 'results.json')

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp_dir)

    def _run_wfp_scan(self):
        return subprocess.run(
            [
                sys.executable, '-m', 'scanoss.cli', 'scan',
                '--wfp', self.wfp_file,
                '--apiurl', self.UNREACHABLE_APIURL,
                '--retry', '0',
                '--timeout', '5',
                '-o', self.output_file,
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )

    def test_wfp_scan_failure_exits_non_zero(self):
        """A failed `--wfp` scan must exit non-zero (Issue 1)."""
        result = self._run_wfp_scan()
        self.assertNotEqual(
            result.returncode, 0,
            f'Expected non-zero exit on scan failure, got 0.\nstderr: {result.stderr}',
        )

    def test_wfp_scan_failure_does_not_write_partial_results(self):
        """A failed `--wfp` scan must not leave partial results behind (Issue 2)."""
        self._run_wfp_scan()
        # The output file is pre-initialised as empty; on failure it must stay
        # empty rather than containing partial/incomplete JSON.
        self.assertEqual(
            os.path.getsize(self.output_file), 0,
            'Failed scan produced non-empty output; partial results were written.',
        )


if __name__ == '__main__':
    unittest.main()
