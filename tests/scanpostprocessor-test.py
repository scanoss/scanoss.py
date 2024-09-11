"""
 SPDX-License-Identifier: MIT

   Copyright (c) 2024, SCANOSS

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

from src.scanoss.scanoss_settings import ScanossSettings
from src.scanoss.scanpostprocessor import ScanPostProcessor


class MyTestCase(unittest.TestCase):
    """
    Unit test cases for Scan Post-Processing
    """

    def test_remove_files(self):
        """
        Should remove files by path from the scan results
        """
        scan_settings = ScanossSettings(filepath="data/scanoss.json")
        post_processor = ScanPostProcessor(scan_settings)
        results = {
            "scanoss_settings.py": [
                {
                    "purl": ["pkg:github/scanoss/scanoss.py"],
                }
            ],
            "test_file_path.go": [
                {
                    "purl": ["pkg:github/scanoss/scanoss.lui"],
                }
            ]
        }
        processed_results = post_processor.load_results(results).post_process()

        self.assertEqual(len(processed_results), 0)
        self.assertEqual(processed_results, {})


if __name__ == '__main__':
    unittest.main()
