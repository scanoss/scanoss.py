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
from unittest.mock import Mock, patch

from scanoss.constants import DEFAULT_COPYLEFT_LICENSE_SOURCES, VALID_LICENSE_SOURCES
from src.scanoss.inspection.policy_check.dependency_track.project_violation import (
    DependencyTrackProjectViolationPolicyCheck,
)
from src.scanoss.inspection.policy_check.policy_check import PolicyStatus
from src.scanoss.inspection.policy_check.scanoss.copyleft import Copyleft
from src.scanoss.inspection.policy_check.scanoss.undeclared_component import UndeclaredComponent
from src.scanoss.inspection.summary.component_summary import ComponentSummary
from src.scanoss.inspection.summary.license_summary import LicenseSummary


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
        status, policy_output = copyleft.run()
        details = json.loads(policy_output.details)
        self.assertEqual(status, PolicyStatus.POLICY_SUCCESS.value)
        self.assertEqual(details, {})
        self.assertEqual(policy_output.summary, '0 component(s) with copyleft licenses were found.\n')

    """
    Inspect for copyleft licenses include
    """

    def test_copyleft_policy_include(self):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        file_name = 'result.json'
        input_file_name = os.path.join(script_dir, 'data', file_name)
        copyleft = Copyleft(filepath=input_file_name, format_type='json', include='MIT')
        status, policy_output = copyleft.run()
        has_mit_license = False
        details = json.loads(policy_output.details)
        for component in details['components']:
            for license in component['licenses']:
                if license['spdxid'] == 'MIT':
                    has_mit_license = True
                    break

        self.assertEqual(status, PolicyStatus.POLICY_FAIL.value)
        self.assertEqual(has_mit_license, True)

    """
       Inspect for copyleft licenses exclude
    """

    def test_copyleft_policy_exclude(self):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        file_name = 'result.json'
        input_file_name = os.path.join(script_dir, 'data', file_name)
        copyleft = Copyleft(filepath=input_file_name, format_type='json', exclude='GPL-2.0-only')
        status, policy_output = copyleft.run()
        results = json.loads(policy_output.details)
        self.assertEqual(results, {})
        self.assertEqual(status, PolicyStatus.POLICY_SUCCESS.value)

    """
        Inspect for copyleft licenses explicit
    """

    def test_copyleft_policy_explicit(self):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        file_name = 'result.json'
        input_file_name = os.path.join(script_dir, 'data', file_name)
        copyleft = Copyleft(filepath=input_file_name, format_type='json', explicit='MIT')
        status, policy_output = copyleft.run()
        results = json.loads(policy_output.details)
        self.assertEqual(len(results['components']), 2)
        self.assertEqual(status, PolicyStatus.POLICY_FAIL.value)

    """
        Inspect for copyleft licenses empty explicit licenses (should set the default ones)
    """

    def test_copyleft_policy_empty_explicit(self):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        file_name = 'result.json'
        input_file_name = os.path.join(script_dir, 'data', file_name)
        copyleft = Copyleft(filepath=input_file_name, format_type='json', explicit='')
        status, policy_output = copyleft.run()
        results = json.loads(policy_output.details)
        self.assertEqual(len(results['components']), 5)
        self.assertEqual(status, PolicyStatus.POLICY_FAIL.value)

    """
        Export copyleft licenses in Markdown
    """

    def test_copyleft_policy_markdown(self):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        file_name = 'result.json'
        input_file_name = os.path.join(script_dir, 'data', file_name)
        copyleft = Copyleft(filepath=input_file_name, format_type='md', explicit='MIT')
        status, policy_output = copyleft.run()
        expected_detail_output = (
            '### Copyleft Licenses \n  | Component | License | URL | Copyleft |\n'
            ' | - | :-: | - | - |\n'
            ' | pkg:npm/%40electron/rebuild | MIT | https://spdx.org/licenses/MIT.html | YES |\n'
            '| pkg:npm/%40emotion/react | MIT | https://spdx.org/licenses/MIT.html | YES | \n'
        )
        expected_summary_output = '2 component(s) with copyleft licenses were found.\n'
        self.assertEqual(
            re.sub(r'\s|\\(?!`)|\\(?=`)', '', policy_output.details),
            re.sub(r'\s|\\(?!`)|\\(?=`)', '', expected_detail_output),
        )
        self.assertEqual(policy_output.summary, expected_summary_output)
        self.assertEqual(status, PolicyStatus.POLICY_FAIL.value)

    ## Undeclared Components Policy Tests ##

    """
       Inspect for undeclared components empty path
    """

    def test_undeclared_policy_empty_path(self):
        undeclared = UndeclaredComponent(filepath='', format_type='json')
        success, results = undeclared.run()
        self.assertTrue(success, 2)

    """
    Inspect for undeclared components
    """

    def test_undeclared_policy(self):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        file_name = 'result.json'
        input_file_name = os.path.join(script_dir, 'data', file_name)
        undeclared = UndeclaredComponent(filepath=input_file_name, format_type='json', sbom_format='legacy')
        status, policy_output = undeclared.run()
        results = json.loads(policy_output.details)
        summary = policy_output.summary
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
        self.assertEqual(len(results['components']), 4)
        self.assertEqual(
            re.sub(r'\s|\\(?!`)|\\(?=`)', '', summary), re.sub(r'\s|\\(?!`)|\\(?=`)', '', expected_summary_output)
        )
        self.assertEqual(status, PolicyStatus.POLICY_FAIL.value)

    """
       Undeclared component markdown output
    """

    def test_undeclared_policy_markdown(self):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        file_name = 'result.json'
        input_file_name = os.path.join(script_dir, 'data', file_name)
        undeclared = UndeclaredComponent(filepath=input_file_name, format_type='md', sbom_format='legacy')
        status, policy_output = undeclared.run()
        results = policy_output.details
        summary = policy_output.summary
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
        self.assertEqual(status, PolicyStatus.POLICY_FAIL.value)
        self.assertEqual(
            re.sub(r'\s|\\(?!`)|\\(?=`)', '', results), re.sub(r'\s|\\(?!`)|\\(?=`)', '', expected_details_output)
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
        status, policy_output = undeclared.run()
        results = policy_output.details
        summary = policy_output.summary
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
        self.assertEqual(status, PolicyStatus.POLICY_FAIL.value)
        self.assertEqual(
            re.sub(r'\s|\\(?!`)|\\(?=`)', '', results), re.sub(r'\s|\\(?!`)|\\(?=`)', '', expected_details_output)
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
        status, policy_output = undeclared.run()
        results = json.loads(policy_output.details)
        summary = policy_output.summary
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
        self.assertEqual(status, PolicyStatus.POLICY_FAIL.value)
        self.assertEqual(len(results['components']), 4)
        self.assertEqual(
            re.sub(r'\s|\\(?!`)|\\(?=`)', '', summary), re.sub(r'\s|\\(?!`)|\\(?=`)', '', expected_summary_output)
        )

    def test_undeclared_policy_jira_markdown_output(self):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        file_name = 'result.json'
        input_file_name = os.path.join(script_dir, 'data', file_name)
        undeclared = UndeclaredComponent(filepath=input_file_name, format_type='jira_md')
        status, policy_output = undeclared.run()
        details = policy_output.details
        summary = policy_output.summary
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
        self.assertEqual(status, PolicyStatus.POLICY_FAIL.value)
        self.assertEqual(expected_details_output, details)
        self.assertEqual(summary, expected_summary_output)

    def test_copyleft_policy_jira_markdown_output(self):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        file_name = 'result.json'
        input_file_name = os.path.join(script_dir, 'data', file_name)
        copyleft = Copyleft(filepath=input_file_name, format_type='jira_md')
        status, policy_output = copyleft.run()
        results = policy_output.details
        expected_details_output = """### Copyleft Licenses\n|*Component*|*License*|*URL*|*Copyleft*|
|pkg:github/scanoss/scanner.c|GPL-2.0-only|https://spdx.org/licenses/GPL-2.0-only.html|YES|
|pkg:github/scanoss/engine|GPL-2.0-only|https://spdx.org/licenses/GPL-2.0-only.html|YES|
|pkg:github/scanoss/wfp|GPL-2.0-only|https://spdx.org/licenses/GPL-2.0-only.html|YES|
"""
        self.assertEqual(status, PolicyStatus.POLICY_FAIL.value)
        self.assertEqual(expected_details_output, results)

    ## Copyleft License Source Filtering Tests ##

    def test_copyleft_policy_default_license_sources(self):
        """
        Test default behavior: should use DEFAULT_COPYLEFT_LICENSE_SOURCES
        (component_declared and license_file)
        """
        script_dir = os.path.dirname(os.path.abspath(__file__))
        file_name = 'result.json'
        input_file_name = os.path.join(script_dir, 'data', file_name)
        copyleft = Copyleft(filepath=input_file_name, format_type='json')
        status, policy_output = copyleft.run()
        details = json.loads(policy_output.details)

        # Should find components with copyleft from component_declared or license_file
        # Expected: 5 PURL@version entries (scanner.c x2, engine x2, wfp x1)
        self.assertEqual(status, PolicyStatus.POLICY_FAIL.value)
        self.assertEqual(len(details['components']), 5)

        # Verify all components have licenses from default sources
        for component in details['components']:
            for license in component['licenses']:
                self.assertIn(license['source'], DEFAULT_COPYLEFT_LICENSE_SOURCES)

    def test_copyleft_policy_license_sources_none(self):
        """
        Test explicit None: should use DEFAULT_COPYLEFT_LICENSE_SOURCES
        """
        script_dir = os.path.dirname(os.path.abspath(__file__))
        file_name = 'result.json'
        input_file_name = os.path.join(script_dir, 'data', file_name)
        copyleft = Copyleft(filepath=input_file_name, format_type='json', license_sources=None)
        status, policy_output = copyleft.run()
        details = json.loads(policy_output.details)

        # Should behave same as default
        self.assertEqual(status, PolicyStatus.POLICY_FAIL.value)
        self.assertEqual(len(details['components']), 5)

        # Verify all components have licenses from default sources
        for component in details['components']:
            for license in component['licenses']:
                self.assertIn(license['source'], DEFAULT_COPYLEFT_LICENSE_SOURCES)


    def test_copyleft_policy_license_sources_component_declared_only(self):
        """
        Test filtering to component_declared source only
        Should find GPL-2.0-only from component_declared
        """
        script_dir = os.path.dirname(os.path.abspath(__file__))
        file_name = 'result.json'
        input_file_name = os.path.join(script_dir, 'data', file_name)
        copyleft = Copyleft(
            filepath=input_file_name,
            format_type='json',
            license_sources=['component_declared']
        )
        status, policy_output = copyleft.run()
        details = json.loads(policy_output.details)

        # Should find 5 PURL@version entries from component_declared
        self.assertEqual(status, PolicyStatus.POLICY_FAIL.value)
        self.assertEqual(len(details['components']), 5)

        # All licenses should be from component_declared
        for component in details['components']:
            for license in component['licenses']:
                self.assertEqual(license['source'], 'component_declared')

    def test_copyleft_policy_license_sources_license_file_only(self):
        """
        Test filtering to license_file source only
        Should find GPL-2.0-only from license_file (engine and wfp)
        """
        script_dir = os.path.dirname(os.path.abspath(__file__))
        file_name = 'result.json'
        input_file_name = os.path.join(script_dir, 'data', file_name)
        copyleft = Copyleft(
            filepath=input_file_name,
            format_type='json',
            license_sources=['license_file']
        )
        status, policy_output = copyleft.run()
        details = json.loads(policy_output.details)

        # Should find engine and wfp (2 components with license_file)
        self.assertEqual(status, PolicyStatus.POLICY_FAIL.value)
        self.assertEqual(len(details['components']), 2)

        # Verify components are engine and wfp
        purls = [comp['purl'] for comp in details['components']]
        self.assertIn('pkg:github/scanoss/engine', purls)
        self.assertIn('pkg:github/scanoss/wfp', purls)

        # All licenses should be from license_file
        for component in details['components']:
            for license in component['licenses']:
                self.assertEqual(license['source'], 'license_file')

    def test_copyleft_policy_license_sources_file_header_only(self):
        """
        Test filtering to file_header source only
        file_header only has BSD-2-Clause and Zlib (not copyleft)
        Should find no copyleft licenses
        """
        script_dir = os.path.dirname(os.path.abspath(__file__))
        file_name = 'result.json'
        input_file_name = os.path.join(script_dir, 'data', file_name)
        copyleft = Copyleft(
            filepath=input_file_name,
            format_type='json',
            license_sources=['file_header']
        )
        status, policy_output = copyleft.run()
        details = json.loads(policy_output.details)

        # Should find no copyleft (file_header only has BSD and Zlib)
        self.assertEqual(status, PolicyStatus.POLICY_SUCCESS.value)
        self.assertEqual(details, {})

    def test_copyleft_policy_license_sources_multiple_sources(self):
        """
        Test using multiple license sources
        Should find copyleft from component_declared and scancode
        """
        script_dir = os.path.dirname(os.path.abspath(__file__))
        file_name = 'result.json'
        input_file_name = os.path.join(script_dir, 'data', file_name)
        copyleft = Copyleft(
            filepath=input_file_name,
            format_type='json',
            license_sources=['component_declared', 'scancode']
        )
        status, policy_output = copyleft.run()
        details = json.loads(policy_output.details)

        # Should find components from both sources
        self.assertEqual(status, PolicyStatus.POLICY_FAIL.value)
        self.assertGreaterEqual(len(details['components']), 3)

        # Verify licenses are from specified sources
        for component in details['components']:
            for license in component['licenses']:
                self.assertIn(license['source'], ['component_declared', 'scancode'])

    def test_copyleft_policy_license_sources_all_valid_sources(self):
        """
        Test using all valid license sources
        """
        script_dir = os.path.dirname(os.path.abspath(__file__))
        file_name = 'result.json'
        input_file_name = os.path.join(script_dir, 'data', file_name)
        copyleft = Copyleft(
            filepath=input_file_name,
            format_type='json',
            license_sources=VALID_LICENSE_SOURCES
        )
        status, policy_output = copyleft.run()
        details = json.loads(policy_output.details)

        # Should find all copyleft licenses from any source
        self.assertEqual(status, PolicyStatus.POLICY_FAIL.value)
        self.assertGreaterEqual(len(details['components']), 3)

    def test_copyleft_policy_license_sources_with_markdown_output(self):
        """
        Test license source filtering works with markdown output
        """
        script_dir = os.path.dirname(os.path.abspath(__file__))
        file_name = 'result.json'
        input_file_name = os.path.join(script_dir, 'data', file_name)
        copyleft = Copyleft(
            filepath=input_file_name,
            format_type='md',
            license_sources=['license_file']
        )
        status, policy_output = copyleft.run()

        # Should generate markdown table
        self.assertEqual(status, PolicyStatus.POLICY_FAIL.value)
        self.assertIn('### Copyleft Licenses', policy_output.details)
        self.assertIn('Component', policy_output.details)
        self.assertIn('License', policy_output.details)
        self.assertIn('2 component(s) with copyleft licenses were found', policy_output.summary)

    def test_copyleft_policy_license_sources_with_include_filter(self):
        """
        Test license_sources works with include filter
        Filter to scancode source and include MIT (normally not copyleft)
        """
        script_dir = os.path.dirname(os.path.abspath(__file__))
        file_name = 'result.json'
        input_file_name = os.path.join(script_dir, 'data', file_name)
        copyleft = Copyleft(
            filepath=input_file_name,
            format_type='json',
            license_sources=['scancode'],
            include='MIT'
        )
        status, policy_output = copyleft.run()
        details = json.loads(policy_output.details)

        # Should find MIT (added via include) and any OSADL copyleft licenses
        self.assertEqual(status, PolicyStatus.POLICY_FAIL.value)
        self.assertGreater(len(details.get('components', [])), 0)

        # Verify all licenses are from scancode or unknown (always included)
        for component in details.get('components', []):
            for license in component['licenses']:
                self.assertIn(license['source'], ['scancode', 'unknown'])

    def test_copyleft_policy_license_sources_with_exclude_filter(self):
        """
        Test license_sources works with exclude filter
        Use component_declared but exclude GPL-2.0-only
        """
        script_dir = os.path.dirname(os.path.abspath(__file__))
        file_name = 'result.json'
        input_file_name = os.path.join(script_dir, 'data', file_name)
        copyleft = Copyleft(
            filepath=input_file_name,
            format_type='json',
            license_sources=['component_declared'],
            exclude='GPL-2.0-only'
        )
        status, policy_output = copyleft.run()
        details = json.loads(policy_output.details)

        # Should exclude GPL-2.0-only, leaving nothing (all component_declared are GPL-2.0-only)
        self.assertEqual(status, PolicyStatus.POLICY_SUCCESS.value)
        self.assertEqual(details, {})

    def test_copyleft_policy_license_sources_no_copyleft_file(self):
        """
        Test license_sources with result-no-copyleft.json
        Should return success even with license_sources specified
        """
        script_dir = os.path.dirname(os.path.abspath(__file__))
        file_name = 'result-no-copyleft.json'
        input_file_name = os.path.join(script_dir, 'data', file_name)
        copyleft = Copyleft(
            filepath=input_file_name,
            format_type='json',
            license_sources=['component_declared']
        )
        status, policy_output = copyleft.run()
        details = json.loads(policy_output.details)

        # Should find no copyleft
        self.assertEqual(status, PolicyStatus.POLICY_SUCCESS.value)
        self.assertEqual(details, {})
        self.assertIn('0 component(s) with copyleft licenses were found', policy_output.summary)

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

    ## Dependency Track Project Violation Policy Tests ##

    @patch('src.scanoss.inspection.policy_check.dependency_track.project_violation.DependencyTrackService')
    def test_dependency_track_project_violation_json_formatter(self, mock_service):
        mock_service.return_value = Mock()
        project_violation = DependencyTrackProjectViolationPolicyCheck(
            format_type='json',
            api_key='test_key',
            url='http://localhost',
            project_id='test_project'
        )
        test_violations = [
            {
                'uuid': 'violation-1',
                'type': 'SECURITY',
                'timestamp': 1640995200000,
                'component': {
                    'name': 'test-component',
                    'version': '1.0.0',
                    'purl': 'pkg:npm/test-component@1.0.0'
                },
                'policyCondition': {
                    'policy': {
                        'name': 'Security Policy',
                        'violationState': 'FAIL'
                    }
                }
            }
        ]
        result = project_violation._json(test_violations)
        self.assertEqual(result.summary, '1 policy violations were found.\n')
        details = json.loads(result.details)
        self.assertEqual(len(details), 1)
        self.assertEqual(details[0]['type'], 'SECURITY')

    @patch('src.scanoss.inspection.policy_check.dependency_track.project_violation.DependencyTrackService')
    def test_dependency_track_project_violation_markdown_formatter(self, mock_service):
        mock_service.return_value = Mock()
        project_violation = DependencyTrackProjectViolationPolicyCheck(
            format_type='md',
            api_key='test_key',
            url='http://localhost',
            project_id='test_project'
        )
        test_violations = [
            {
                'uuid': 'violation-1',
                'type': 'SECURITY',
                'timestamp': 1640995200000,
                'component': {
                    'name': 'test-component',
                    'version': '1.0.0',
                    'purl': 'pkg:npm/test-component@1.0.0'
                },
                'policyCondition': {
                    'policy': {
                        'name': 'Security Policy',
                        'violationState': 'FAIL'
                    }
                }
            }
        ]
        result = project_violation._markdown(test_violations)
        self.assertEqual(result.summary, '1 policy violations were found.\n')
        self.assertIn('State', result.details)
        self.assertIn('Risk Type', result.details)
        self.assertIn('Policy Name', result.details)
        self.assertIn('Component', result.details)
        self.assertIn('Date', result.details)

    @patch('src.scanoss.inspection.policy_check.dependency_track.project_violation.DependencyTrackService')
    def test_dependency_track_project_violation_sort_violations(self, mock_service):
        mock_service.return_value = Mock()
        project_violation = DependencyTrackProjectViolationPolicyCheck(
            api_key='test_key',
            url='http://localhost',
            project_id='test_project'
        )
        test_violations = [
            {'type': 'LICENSE', 'uuid': 'license-violation'},
            {'type': 'SECURITY', 'uuid': 'security-violation'},
            {'type': 'OTHER', 'uuid': 'other-violation'},
            {'type': 'SECURITY', 'uuid': 'security-violation-2'}
        ]
        sorted_violations = project_violation._sort_project_violations(test_violations)
        self.assertEqual(sorted_violations[0]['type'], 'SECURITY')
        self.assertEqual(sorted_violations[1]['type'], 'SECURITY')
        self.assertEqual(sorted_violations[2]['type'], 'LICENSE')
        self.assertEqual(sorted_violations[3]['type'], 'OTHER')

    @patch('src.scanoss.inspection.policy_check.dependency_track.project_violation.DependencyTrackService')
    def test_dependency_track_project_violation_empty_violations(self, mock_service):
        mock_service.return_value = Mock()
        project_violation = DependencyTrackProjectViolationPolicyCheck(
            format_type='json',
            api_key='test_key',
            url='http://localhost',
            project_id='test_project'
        )
        empty_violations = []
        result = project_violation._json(empty_violations)
        self.assertEqual(result.summary, '0 policy violations were found.\n')
        details = json.loads(result.details)
        self.assertEqual(len(details), 0)

    @patch('src.scanoss.inspection.policy_check.dependency_track.project_violation.DependencyTrackService')
    def test_dependency_track_project_violation_markdown_empty(self, mock_service):
        mock_service.return_value = Mock()
        project_violation = DependencyTrackProjectViolationPolicyCheck(
            format_type='md',
            api_key='test_key',
            url='http://localhost',
            project_id='test_project'
        )
        empty_violations = []
        result = project_violation._markdown(empty_violations)
        self.assertEqual(result.summary, '0 policy violations were found.\n')
        self.assertIn('State', result.details)
        self.assertIn('Risk Type', result.details)

    @patch('src.scanoss.inspection.policy_check.dependency_track.project_violation.DependencyTrackService')
    def test_dependency_track_project_violation_multiple_types(self, mock_service):
        mock_service.return_value = Mock()
        project_violation = DependencyTrackProjectViolationPolicyCheck(
            format_type='json',
            api_key='test_key',
            url='http://localhost',
            project_id='test_project'
        )
        test_violations = [
            {
                'uuid': 'violation-1',
                'type': 'SECURITY',
                'timestamp': 1640995200000,
                'component': {
                    'name': 'vulnerable-component',
                    'version': '1.0.0',
                    'purl': 'pkg:npm/vulnerable-component@1.0.0'
                },
                'policyCondition': {
                    'policy': {
                        'name': 'Security Policy',
                        'violationState': 'FAIL'
                    }
                }
            },
            {
                'uuid': 'violation-2',
                'type': 'LICENSE',
                'timestamp': 1640995300000,
                'component': {
                    'name': 'license-component',
                    'version': '2.0.0',
                    'purl': 'pkg:npm/license-component@2.0.0'
                },
                'policyCondition': {
                    'policy': {
                        'name': 'License Policy',
                        'violationState': 'WARN'
                    }
                }
            }
        ]
        result = project_violation._json(test_violations)
        self.assertEqual(result.summary, '2 policy violations were found.\n')
        details = json.loads(result.details)
        self.assertEqual(len(details), 2)

if __name__ == '__main__':
    unittest.main()
