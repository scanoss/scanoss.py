import unittest

from scanoss.winnowing import Winnowing
import time

class MyTestCase(unittest.TestCase):
    maxDiff=None
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

    def test_winnowing_c(self):
        winnowing = Winnowing(debug=True, c_accelerated=True)
        filename = "test-file.py"
        with open(__file__, 'rb') as f:
            contents = f.read()
        wfp = winnowing.wfp_for_contents(filename, False, contents)

        winnowing = Winnowing(debug=True, c_accelerated=False)
        wfp_expected = winnowing.wfp_for_contents(filename, False, contents)
        self.assertEqual(wfp, wfp_expected)


    def test_winnowing_timings(self):
        winnowing = Winnowing(debug=True, c_accelerated=True)
        filename = "test-file.py"
        with open(__file__, 'rb') as f:
            contents = f.read()
        t1 = time.time()
        for i in range(1000):
            wfp = winnowing.wfp_for_contents(filename, False, contents)
        t2 = time.time()
        x1 = t2-t1
        winnowing = Winnowing(debug=True, c_accelerated=False)
        t1 = time.time()
        for i in range(100):
            wfp_expected = winnowing.wfp_for_contents(filename, False, contents)
        t2 = time.time()
        x2 = t2-t1
        print(x1, x2, 10*x2/x1)
        self.assertEqual(wfp, wfp_expected)

    def test_snippet_skip(self):
        winnowing = Winnowing(debug=True)
        filename = "test-file.jar"
        contents = "jar file contents"
        content_types = bytes(contents, encoding="raw_unicode_escape")
        wfp = winnowing.wfp_for_contents(filename, False, content_types)
        print(f'WFP for {filename}: {wfp}')
        self.assertIsNotNone(wfp)

    def test_normalize(self):
        res = bytes([Winnowing._normalize(i) for i in range(255)])
        exp = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x000123456789\x00\x00\x00\x00\x00\x00\x00abcdefghijklmnopqrstuvwxyz\x00\x00\x00\x00\x00\x00abcdefghijklmnopqrstuvwxyz\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        self.assertEqual(res, exp)


if __name__ == '__main__':
    unittest.main()
