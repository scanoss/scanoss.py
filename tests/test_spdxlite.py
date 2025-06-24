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
import json
import os
import tempfile
import unittest

from scanoss.spdxlite import SpdxLite


class MyTestCase(unittest.TestCase):
    """
    Exercise the SpdxLite class
    """
    def testSpdxLite(self):
        temp_dir = tempfile.gettempdir()
        spdx_lite_output = os.path.join(temp_dir, "spdxlite.json")
        test_data_dir = os.path.dirname(os.path.abspath(__file__))
        file_name = 'result.json'
        input_file_name = os.path.join(test_data_dir, 'data', file_name)
        spdx_lite = SpdxLite(debug = False, output_file=spdx_lite_output)
        spdx_lite.produce_from_file(input_file_name)
        md5_length = 32
        # Read data using absolute path
        with open(spdx_lite_output, 'r') as f:
            parsed_data = json.load(f)
            spdx_version = parsed_data.get("spdxVersion")
            spdx_id = parsed_data.get("SPDXID")
            name = parsed_data.get("name")
            organization = parsed_data.get("creationInfo",{}).get('creators')[2]
            creation_info_comment = parsed_data.get("creationInfo", {}).get('comment')
            document_describes = parsed_data.get("documentDescribes")
            packages = parsed_data.get("packages")

            self.assertEqual(spdx_version, "SPDX-2.2")
            self.assertEqual(spdx_id, "SPDXRef-DOCUMENT")
            self.assertEqual(name, "SCANOSS-SBOM")
            self.assertEqual(organization, "Organization: SCANOSS")
            self.assertEqual(creation_info_comment, "SBOM Build information - SBOM Type: Build")
            self.assertEqual(len(document_describes), 6)
            self.assertEqual(len(packages), 6)

            for package in packages:
                for checksum in package.get("checksums", []):
                    self.assertEqual(checksum.get("algorithm"), "MD5") #Check all algorithms be MD5
                    self.assertEqual(len(checksum.get("checksumValue")), md5_length) #Check checksum length value be 32


        os.remove(spdx_lite_output) #Removes tmp spdxlite.json file