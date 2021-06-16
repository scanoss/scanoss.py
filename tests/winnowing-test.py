import unittest

from scanoss.winnowing import Winnowing


class MyTestCase(unittest.TestCase):
    def test_winnowing(self):
        winnowing = Winnowing()
        filename = "test-file.c"
        contents = "c code contents"
        content_types = bytes(contents, encoding="raw_unicode_escape")
        wfp = winnowing.wfp_for_contents(filename, content_types)
        print(f'WFP for {filename}:')
        print(wfp)
        filename = __file__
        wfp = winnowing.wfp_for_file(filename, filename)
        print(f'WFP for {filename}:')
        print(wfp)

        self.assertEqual(True, False)


if __name__ == '__main__':
    unittest.main()
