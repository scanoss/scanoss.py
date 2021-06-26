import unittest

from scanoss.winnowing import Winnowing


class MyTestCase(unittest.TestCase):
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


if __name__ == '__main__':
    unittest.main()
