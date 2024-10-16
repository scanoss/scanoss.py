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
import json
import os
import unittest

from scanoss.inspection.copyleft import Copyleft


class MyTestCase(unittest.TestCase):
    """
    Inspect for copyleft licenses
    """
    def test_copyleft_policy(self):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        file_name = "result.json"
        input_file_name = os.path.join(script_dir,'data', file_name)
        copyleft = Copyleft(filepath=input_file_name, format='json')
        copyleft.run()
        self.assertEqual(True, True)


    """
    Inspect for empty copyleft licenses
    """
    def test_empty_copyleft_policy(self):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        file_name = "result-no-copyleft.json"
        input_file_name = os.path.join(script_dir,'data', file_name)
        copyleft = Copyleft(filepath=input_file_name, format='json')
        results = copyleft.run()
        details = json.loads(results['details'])
        self.assertEqual(details, {})
        self.assertEqual(results['summary'], '')

    """
    Inspect for copyleft licenses include
    """
    def test_copyleft_policy_include(self):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        file_name = "result.json"
        input_file_name = os.path.join(script_dir, 'data', file_name)
        copyleft = Copyleft(filepath=input_file_name, format='json', include='MIT')
        results = copyleft.run()
        has_mit_license = False
        details = json.loads(results['details'])
        for component in details['components']:
            for license in component['licenses']:
                if license['spdxid'] == 'MIT':
                    has_mit_license = True
                    break

        self.assertEqual(has_mit_license, True)

    """
       Inspect for copyleft licenses exclude
    """
    def test_copyleft_policy_exclude(self):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        file_name = "result.json"
        input_file_name = os.path.join(script_dir, 'data', file_name)
        copyleft = Copyleft(filepath=input_file_name, format='json', exclude='GPL-2.0-only')
        results = copyleft.run()
        details = json.loads(results['details'])
        self.assertEqual(details, {})

    """
        Inspect for copyleft licenses explicit
    """
    def test_copyleft_policy_explicit(self):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        file_name = "result.json"
        input_file_name = os.path.join(script_dir, 'data', file_name)
        copyleft = Copyleft(filepath=input_file_name, format='json', explicit='MIT')
        results = copyleft.run()
        details = json.loads(results['details'])
        self.assertEqual(len(details['components']), 1)


    """
        Export copyleft licenses in Markdown
    """
    def test_copyleft_policy_markdown(self):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        file_name = "result.json"
        input_file_name = os.path.join(script_dir, 'data', file_name)
        copyleft = Copyleft(filepath=input_file_name, format='md', explicit='MIT')
        results = copyleft.run()
        expected_detail_output = '### Copyleft licenses \n  | Component | Version | License | URL | Copyleft | \n | - | :-: | - | - | :-: | \n | pkg:github/scanoss/engine | 4.0.4 | MIT | https://spdx.org/licenses/MIT.html | YES | '
        expected_summary_output = '1 component(s) with copyleft licenses were found.'
        self.assertEqual(results['details'], expected_detail_output)
        self.assertEqual(results['summary'], expected_summary_output)