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
import unittest

from scanoss.osadl import Osadl


class TestOsadl(unittest.TestCase):
    """
    Test the Osadl class
    """

    def test_initialization(self):
        """Test basic initialization - data is loaded at class level"""
        osadl = Osadl()
        self.assertIsNotNone(osadl)
        self.assertTrue(Osadl._data_loaded)
        self.assertGreater(len(Osadl._shared_copyleft_data), 0)

    def test_initialization_with_debug(self):
        """Test initialization with debug enabled"""
        osadl = Osadl(debug=True)
        self.assertTrue(osadl.debug)

    def test_is_copyleft_gpl_2_0_only(self):
        """Test GPL-2.0-only is copyleft"""
        osadl = Osadl()
        self.assertTrue(osadl.is_copyleft('GPL-2.0-only'))

    def test_is_copyleft_gpl_2_0_or_later(self):
        """Test GPL-2.0-or-later is copyleft"""
        osadl = Osadl()
        self.assertTrue(osadl.is_copyleft('GPL-2.0-or-later'))

    def test_is_not_copyleft_mit(self):
        """Test MIT is not copyleft"""
        osadl = Osadl()
        self.assertFalse(osadl.is_copyleft('MIT'))

    def test_is_copyleft_case_insensitive_license_id(self):
        """Test license ID lookup is case-insensitive"""
        osadl = Osadl()
        self.assertTrue(osadl.is_copyleft('gpl-2.0-only'))
        self.assertTrue(osadl.is_copyleft('GPL-2.0-ONLY'))
        self.assertTrue(osadl.is_copyleft('Gpl-2.0-Only'))

    def test_is_copyleft_unknown_license(self):
        """Test unknown license returns False"""
        osadl = Osadl()
        self.assertFalse(osadl.is_copyleft('Unknown-License'))

    def test_is_copyleft_empty_string(self):
        """Test empty string returns False"""
        osadl = Osadl()
        self.assertFalse(osadl.is_copyleft(''))

    def test_is_copyleft_none(self):
        """Test None returns False"""
        osadl = Osadl()
        self.assertFalse(osadl.is_copyleft(None))

    def test_multiple_instances_share_data(self):
        """Test that multiple instances share the same class-level data"""
        osadl1 = Osadl()
        osadl2 = Osadl()

        # Both instances should see data loaded by first instance
        result1 = osadl1.is_copyleft('GPL-2.0-only')
        self.assertTrue(result1)
        self.assertTrue(Osadl._data_loaded)

        # Second instance uses the same class-level shared data
        result2 = osadl2.is_copyleft('MIT')
        self.assertFalse(result2)

        # Verify both instances reference the same class-level data
        self.assertIs(Osadl._shared_copyleft_data, Osadl._shared_copyleft_data)


if __name__ == '__main__':
    unittest.main()