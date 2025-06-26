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

import json
import os
import re
import unittest

from scanoss.inspection.copyleft import Copyleft
from scanoss.inspection.license_summary import LicenseSummary
from scanoss.inspection.undeclared_component import UndeclaredComponent

from src.scanoss.inspection.component_summary import ComponentSummary


class MyTestCase(unittest.TestCase):
    """
    Inspect for copyleft licenses
    """

    def test_copyleft_policy(self):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        file_name = 'result.json'
        input_file_name = os.path.join(script_dir, 'data', file_name)
        copyleft = Copyleft(filepath=input_file_name, format_type='json')
        copyleft.run()
        self.assertEqual(True, True)

    """
       Inspect for copyleft licenses empty path
    """

    def test_copyleft_policy_empty_path(self):
        copyleft = Copyleft(filepath='', format_type='json')
        success, results = copyleft.run()
        self.assertTrue(success, 2)

    """
    Inspect for empty copyleft licenses
    """

    def test_empty_copyleft_policy(self):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        file_name = 'result-no-copyleft.json'
        input_file_name = os.path.join(script_dir, 'data', file_name)
        copyleft = Copyleft(filepath=input_file_name, format_type='json')
        status, results = copyleft.run()
        details = json.loads(results['details'])
        self.assertEqual(status, 1)
        self.assertEqual(details, {})
        self.assertEqual(results['summary'], '0 component(s) with copyleft licenses were found.\n')

    """
    Inspect for copyleft licenses include
    """

    def test_copyleft_policy_include(self):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        file_name = 'result.json'
        input_file_name = os.path.join(script_dir, 'data', file_name)
        copyleft = Copyleft(filepath=input_file_name, format_type='json', include='MIT')
        status, results = copyleft.run()
        has_mit_license = False
        details = json.loads(results['details'])
        for component in details['components']:
            for license in component['licenses']:
                if license['spdxid'] == 'MIT':
                    has_mit_license = True
                    break

        self.assertEqual(status, 0)
        self.assertEqual(has_mit_license, True)

    """
       Inspect for copyleft licenses exclude
    """

    def test_copyleft_policy_exclude(self):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        file_name = 'result.json'
        input_file_name = os.path.join(script_dir, 'data', file_name)
        copyleft = Copyleft(filepath=input_file_name, format_type='json', exclude='GPL-2.0-only')
        status, results = copyleft.run()
        details = json.loads(results['details'])
        self.assertEqual(details, {})
        self.assertEqual(status, 1)

    """
        Inspect for copyleft licenses explicit
    """

    def test_copyleft_policy_explicit(self):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        file_name = 'result.json'
        input_file_name = os.path.join(script_dir, 'data', file_name)
        copyleft = Copyleft(filepath=input_file_name, format_type='json', explicit='MIT')
        status, results = copyleft.run()
        details = json.loads(results['details'])
        self.assertEqual(len(details['components']), 2)
        self.assertEqual(status, 0)

    """
        Inspect for copyleft licenses empty explicit licenses (should set the default ones)
    """

    def test_copyleft_policy_empty_explicit(self):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        file_name = 'result.json'
        input_file_name = os.path.join(script_dir, 'data', file_name)
        copyleft = Copyleft(filepath=input_file_name, format_type='json', explicit='')
        status, results = copyleft.run()
        details = json.loads(results['details'])
        self.assertEqual(len(details['components']), 5)
        self.assertEqual(status, 0)

    """
        Export copyleft licenses in Markdown
    """

    def test_copyleft_policy_markdown(self):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        file_name = 'result.json'
        input_file_name = os.path.join(script_dir, 'data', file_name)
        copyleft = Copyleft(filepath=input_file_name, format_type='md', explicit='MIT')
        status, results = copyleft.run()
        expected_detail_output = (
            '### Copyleft licenses \n  | Component | License | URL | Copyleft |\n'
            ' | - | :-: | - | - |\n'
            ' | pkg:npm/%40electron/rebuild | MIT | https://spdx.org/licenses/MIT.html | YES |\n'
            '| pkg:npm/%40emotion/react | MIT | https://spdx.org/licenses/MIT.html | YES | \n'
        )
        expected_summary_output = '2 component(s) with copyleft licenses were found.\n'
        self.assertEqual(
            re.sub(r'\s|\\(?!`)|\\(?=`)', '', results['details']),
            re.sub(r'\s|\\(?!`)|\\(?=`)', '', expected_detail_output),
        )
        self.assertEqual(results['summary'], expected_summary_output)
        self.assertEqual(status, 0)

    ## Undeclared Components Policy Tests ##

    """
       Inspect for undeclared components empty path
    """

    def test_copyleft_policy_empty_path(self):
        copyleft = Copyleft(filepath='', format_type='json')
        success, results = copyleft.run()
        self.assertTrue(success, 2)

    """
    Inspect for undeclared components
    """

    def test_undeclared_policy(self):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        file_name = 'result.json'
        input_file_name = os.path.join(script_dir, 'data', file_name)
        undeclared = UndeclaredComponent(filepath=input_file_name, format_type='json', sbom_format='legacy')
        status, results = undeclared.run()
        details = json.loads(results['details'])
        summary = results['summary']
        expected_summary_output = """3 undeclared component(s) were found.
        Add the following snippet into your `sbom.json` file 
        ```json 
        {
            "components":[
                  {
                    "purl": "pkg:github/scanoss/jenkins-pipeline-example"
                  },
                  {
                    "purl": "pkg:github/scanoss/scanner.c"
                  },
                  {
                    "purl": "pkg:github/scanoss/wfp"
                  }
            ]
        }```
        """
        self.assertEqual(len(details['components']), 4)
        self.assertEqual(
            re.sub(r'\s|\\(?!`)|\\(?=`)', '', summary), re.sub(r'\s|\\(?!`)|\\(?=`)', '', expected_summary_output)
        )
        self.assertEqual(status, 0)

    """
       Undeclared component markdown output
    """

    def test_undeclared_policy_markdown(self):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        file_name = 'result.json'
        input_file_name = os.path.join(script_dir, 'data', file_name)
        undeclared = UndeclaredComponent(filepath=input_file_name, format_type='md', sbom_format='legacy')
        status, results = undeclared.run()
        details = results['details']
        summary = results['summary']
        expected_details_output = """ ### Undeclared components
             | Component | License | 
             | - | - | 
             | pkg:github/scanoss/jenkins-pipeline-example | unknown | 
             | pkg:github/scanoss/scanner.c | GPL-2.0-only | 
             | pkg:github/scanoss/wfp | GPL-2.0-only |  """

        expected_summary_output = """3 undeclared component(s) were found.
           Add the following snippet into your `sbom.json` file 
           ```json 
               {
                "components":[
                 {
                    "purl": "pkg:github/scanoss/jenkins-pipeline-example"
                 },
                 {
                    "purl": "pkg:github/scanoss/scanner.c"
                  },
                  {
                    "purl": "pkg:github/scanoss/wfp"
                  }         
                ]             
               }```
           """
        self.assertEqual(status, 0)
        self.assertEqual(
            re.sub(r'\s|\\(?!`)|\\(?=`)', '', details), re.sub(r'\s|\\(?!`)|\\(?=`)', '', expected_details_output)
        )
        self.assertEqual(
            re.sub(r'\s|\\(?!`)|\\(?=`)', '', summary), re.sub(r'\s|\\(?!`)|\\(?=`)', '', expected_summary_output)
        )

    """
         Undeclared component markdown scanoss summary output
    """

    def test_undeclared_policy_markdown_scanoss_summary(self):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        file_name = 'result.json'
        input_file_name = os.path.join(script_dir, 'data', file_name)
        undeclared = UndeclaredComponent(filepath=input_file_name, format_type='md')
        status, results = undeclared.run()
        details = results['details']
        summary = results['summary']
        expected_details_output = """ ### Undeclared components
               | Component | License | 
               | - | - | 
               | pkg:github/scanoss/jenkins-pipeline-example | unknown |
               | pkg:github/scanoss/scanner.c | GPL-2.0-only | 
               | pkg:github/scanoss/wfp | GPL-2.0-only | """

        expected_summary_output = """3 undeclared component(s) were found.
            Add the following snippet into your `scanoss.json` file
            
            ```json
            {
              "bom": {
                "include": [
                  {
                    "purl": "pkg:github/scanoss/jenkins-pipeline-example"
                  },
                  {
                    "purl": "pkg:github/scanoss/scanner.c"
                  },
                  {
                    "purl": "pkg:github/scanoss/wfp"
                  }
                ]
              }
            }
            ```"""
        self.assertEqual(status, 0)
        self.assertEqual(
            re.sub(r'\s|\\(?!`)|\\(?=`)', '', details), re.sub(r'\s|\\(?!`)|\\(?=`)', '', expected_details_output)
        )
        self.assertEqual(
            re.sub(r'\s|\\(?!`)|\\(?=`)', '', summary), re.sub(r'\s|\\(?!`)|\\(?=`)', '', expected_summary_output)
        )

    """
        Undeclared component sbom summary output
    """

    def test_undeclared_policy_scanoss_summary(self):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        file_name = 'result.json'
        input_file_name = os.path.join(script_dir, 'data', file_name)
        undeclared = UndeclaredComponent(filepath=input_file_name)
        status, results = undeclared.run()
        details = json.loads(results['details'])
        summary = results['summary']
        expected_summary_output = """3 undeclared component(s) were found.
                Add the following snippet into your `scanoss.json` file

                ```json
                {
                  "bom": {
                    "include": [
                      {
                        "purl": "pkg:github/scanoss/jenkins-pipeline-example"
                      },
                      {
                        "purl": "pkg:github/scanoss/scanner.c"
                      },
                      {
                        "purl": "pkg:github/scanoss/wfp"
                      }
                    ]
                  }
                }
                ```"""
        self.assertEqual(status, 0)
        self.assertEqual(len(details['components']), 4)
        self.assertEqual(
            re.sub(r'\s|\\(?!`)|\\(?=`)', '', summary), re.sub(r'\s|\\(?!`)|\\(?=`)', '', expected_summary_output)
        )

    def test_undeclared_policy_jira_markdown_output(self):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        file_name = 'result.json'
        input_file_name = os.path.join(script_dir, 'data', file_name)
        undeclared = UndeclaredComponent(filepath=input_file_name, format_type='jira_md')
        status, results = undeclared.run()
        details = results['details']
        summary = results['summary']
        expected_details_output = """|*Component*|*License*|
|pkg:github/scanoss/jenkins-pipeline-example|unknown|
|pkg:github/scanoss/scanner.c|GPL-2.0-only|
|pkg:github/scanoss/wfp|GPL-2.0-only|
"""
        expected_summary_output = """3 undeclared component(s) were found.
Add the following snippet into your `scanoss.json` file
{code:json}
{
  "bom": {
    "include": [
      {
        "purl": "pkg:github/scanoss/jenkins-pipeline-example"
      },
      {
        "purl": "pkg:github/scanoss/scanner.c"
      },
      {
        "purl": "pkg:github/scanoss/wfp"
      }
    ]
  }
}
{code}
"""
        self.assertEqual(status, 0)
        self.assertEqual(expected_details_output, details)
        self.assertEqual(summary, expected_summary_output)

    def test_copyleft_policy_jira_markdown_output(self):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        file_name = 'result.json'
        input_file_name = os.path.join(script_dir, 'data', file_name)
        copyleft = Copyleft(filepath=input_file_name, format_type='jira_md')
        status, results = copyleft.run()
        details = results['details']
        expected_details_output = """|*Component*|*License*|*URL*|*Copyleft*|
|pkg:github/scanoss/scanner.c|GPL-2.0-only|https://spdx.org/licenses/GPL-2.0-only.html|YES|
|pkg:github/scanoss/engine|GPL-2.0-only|https://spdx.org/licenses/GPL-2.0-only.html|YES|
|pkg:github/scanoss/wfp|GPL-2.0-only|https://spdx.org/licenses/GPL-2.0-only.html|YES|
"""
        self.assertEqual(status, 0)
        self.assertEqual(expected_details_output, details)

    def test_inspect_license_summary(self):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        file_name = 'result.json'
        input_file_name = os.path.join(script_dir, 'data', file_name)
        i_license_summary = LicenseSummary(filepath=input_file_name)
        license_summary = i_license_summary.run()
        self.assertEqual(license_summary['detectedLicenses'], 3)
        self.assertEqual(license_summary['detectedLicensesWithCopyleft'], 1)

    def test_inspect_license_summary_with_empty_result(self):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        file_name = 'empty-result.json'
        input_file_name = os.path.join(script_dir, 'data', file_name)
        i_license_summary = LicenseSummary(filepath=input_file_name)
        license_summary = i_license_summary.run()
        self.assertEqual(license_summary['detectedLicenses'], 0)
        self.assertEqual(license_summary['detectedLicensesWithCopyleft'], 0)
        self.assertEqual(len(license_summary['licenses']), 0)

    def test_inspect_component_summary(self):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        file_name = 'result.json'
        input_file_name = os.path.join(script_dir, 'data', file_name)
        i_component_summary = ComponentSummary(filepath=input_file_name)
        component_summary = i_component_summary.run()
        print(component_summary)
        self.assertEqual(component_summary['totalComponents'], 4)
        self.assertEqual(component_summary['undeclaredComponents'], 3)
        self.assertEqual(component_summary['declaredComponents'], 1)
        self.assertEqual(component_summary['totalFilesDetected'], 10)
        self.assertEqual(component_summary['totalFilesUndeclared'], 8)
        self.assertEqual(component_summary['totalFilesDeclared'], 2)

    def test_inspect_component_summary_empty_result(self):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        file_name = 'empty-result.json'
        input_file_name = os.path.join(script_dir, 'data', file_name)
        i_component_summary = ComponentSummary(filepath=input_file_name)
        component_summary = i_component_summary.run()
        self.assertEqual(component_summary['totalComponents'], 0)
        self.assertEqual(component_summary['undeclaredComponents'], 0)
        self.assertEqual(component_summary['declaredComponents'], 0)
        self.assertEqual(len(component_summary['components']), 0)
        self.assertEqual(component_summary['totalFilesDetected'], 0)
        self.assertEqual(component_summary['totalFilesUndeclared'], 0)
        self.assertEqual(component_summary['totalFilesDeclared'], 0)

if __name__ == '__main__':
    unittest.main()
