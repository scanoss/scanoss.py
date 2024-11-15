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

from scanoss.winnowing import Winnowing


class MyTestCase(unittest.TestCase):
    """
    Exercise the Winnowing class
    """
    def test_winnowing(self):
        winnowing = Winnowing(debug=True)
        filename = "test-file.c"
        contents = "c code contents"
        content_types = bytes(contents, encoding="raw_unicode_escape")
        wfp = winnowing.wfp_for_contents(filename, False, content_types)
        print(f'WFP for {filename}: {wfp}')
        self.assertIsNotNone(wfp)
        filename = __file__
        wfp = winnowing.wfp_for_file(filename, filename)
        print(f'WFP for {filename}: {wfp}')
        self.assertIsNotNone(wfp)

    def test_snippet_skip(self):
        winnowing = Winnowing(debug=True)
        filename = "test-file.jar"
        contents = "jar file contents"
        content_types = bytes(contents, encoding="raw_unicode_escape")
        wfp = winnowing.wfp_for_contents(filename, False, content_types)
        print(f'WFP for {filename}: {wfp}')
        self.assertIsNotNone(wfp)
    
    def test_snippet_strip(self):
        winnowing = Winnowing(debug=True, hpsm=True,
                              strip_snippet_ids=['d5e54c33,b03faabe'], 
                              strip_hpsm_ids=['0d2fffaffc62d18'])
        filename = "test-file.py"
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



if __name__ == '__main__':
    unittest.main()
