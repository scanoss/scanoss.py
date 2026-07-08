"""
SPDX-License-Identifier: MIT

  Copyright (c) 2026, SCANOSS

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
import ast
import json
import re
from typing import List, Optional, TypedDict

from ....services.hermine_service import HermineService
from ...utils.markdown_utils import generate_jira_table, generate_table
from ..policy_check import PolicyCheck, PolicyOutput, PolicyStatus

# Constants
DEFAULT_TIME_OUT = 300.0

"""
Hermine violation policy check implementation.

This module provides policy checking functionality for Hermine violations.
It retrieves, processes, and formats policy violations from a Hermine instance
for a specific project.
"""


# TODO: define Hermine response schema — replace these stubs with actual API response fields
class HermineViolationDict(TypedDict):
    """TypedDict for violation information from Hermine."""
    pass


class HermineViolationsPolicyCheck(PolicyCheck[HermineViolationDict]):
    """
    Policy check implementation for Hermine violations.

    This class handles retrieving, processing, and formatting policy violations
    from a Hermine instance for a specific project.
    """

    def __init__(  # noqa: PLR0913
            self,
            debug: bool = False,
            trace: bool = False,
            quiet: bool = False,
            product_name: str = None,
            release_name: str = None,
            product_id: int = None,
            release_id: int = None,
            api_key: str = None,
            url: str = None,
            timeout: float = DEFAULT_TIME_OUT,
            format_type: str = None,
            status: str = None,
            output: str = None,
    ):
        """
        Initialise the Hermine violation policy checker.

        Args:
            debug: Enable debug output
            trace: Enable trace output
            quiet: Enable quiet mode
            product_name: Name of the product in Hermine
            release_name: Release of the product in Hermine
            product_id: Hermine product ID (alternative to product_name/release_name)
            release_id: Hermine release ID (alternative to product_name/release_name)
            api_key: API key for Hermine authentication
            url: Base URL of the Hermine instance
            format_type: Output format type (json, markdown, etc.)
            status: Status output destination
            output: Results output destination
            timeout: Timeout for processing in seconds (default: 300)
        """
        super().__init__(debug, trace, quiet, format_type, status, 'hermine', output)
        self.api_key = api_key
        self.product_name = product_name
        self.release_name = release_name
        self.product_id = product_id
        self.release_id = release_id
        self.timeout = timeout
        self.url = url.strip().rstrip('/') if url else None
        self.hm_service = HermineService(
            self.api_key, self.url, debug=debug, trace=trace, quiet=quiet, timeout=self.timeout
        )

    def _json(self, violations: list[HermineViolationDict]) -> PolicyOutput:
        """
        Format violations as JSON.

        Args:
            violations: List of violations from Hermine

        Returns:
            PolicyOutput containing JSON formatted results and summary
        """
        return PolicyOutput(
            details=json.dumps(violations, indent=2),
            summary=f'{len(violations)} policy violations were found.\n',
        )

    def _markdown(self, violations: list[HermineViolationDict]) -> PolicyOutput:
        """
        Format Hermine violations to Markdown format.

        Args:
            violations: List of violations from Hermine

        Returns:
            PolicyOutput with formatted Markdown details and summary
        """
        return self._md_summary_generator(violations, generate_table)

    def _jira_markdown(self, violations: list[HermineViolationDict]) -> PolicyOutput:
        """
        Format violations for Jira Markdown.

        Args:
            violations: List of violations from Hermine

        Returns:
            PolicyOutput containing Jira markdown formatted results and summary
        """
        return self._md_summary_generator(violations, generate_jira_table)


    def _md_summary_generator(self, violations: list[dict], table_generator) -> PolicyOutput:
        """
        Generates a Markdown summary of Hermine policy violations.

        Args:
            violations: Flat list of violations with category, purl, license_expression, scope, project
            table_generator: Callable that generates the Markdown table

        Returns:
            PolicyOutput with formatted Markdown details and summary
        """
        if not violations:
            return PolicyOutput(
                details="### Hermine Violations\n\nNo policy violations found.\n",
                summary="0 policy violations were found.\n",
            )
        headers = ['Category', 'Component', 'License Expression', 'Scope', 'Project']
        c_cols = [0]
        rows: List[List[str]] = [
            [
                v.get('category', ''),
                v.get('purl', ''),
                v.get('license_expression', ''),
                v.get('scope', ''),
                v.get('project', ''),
            ]
            for v in violations
        ]
        return PolicyOutput(
            details=f'### Hermine Violations\n{table_generator(headers, rows, c_cols)}\n\n'
                    f'View release in Hermine [here]({self.url}/releases/{self.release_id}).\n',
            summary=f'{len(violations)} policy violation(s) were found.\n',
        )

    def _handle_validation_1(self, response: Optional[dict]) -> list[dict]:
        """Step 1: Components with invalid SPDX license expressions."""
        link = response.get('details', '') if response else ''
        components = [
            {
                'purl': item.get('version', {}).get('purl', ''),
                'declared_license_expr': item.get('version', {}).get('declared_license_expr', ''),
            }
            for item in (response or {}).get('invalid_expressions', [])
        ]
        self.print_stderr(
            f'Step 1 failed: {len(components)} component(s) have invalid SPDX license expressions — fix in Hermine.\n'
            f'Link: {self.url}{link}'
        )
        return components

    def _handle_validation_2(self, response: Optional[dict]) -> list[dict]:
        """Step 2: AND license expressions that need to be confirmed."""
        link = response.get('details', '') if response else ''
        components = [
            {
                'purl': item.get('version', {}).get('purl', ''),
                'spdx_valid_license_expr': item.get('version', {}).get('spdx_valid_license_expr', ''),
            }
            for item in (response or {}).get('to_confirm', [])
        ]
        self.print_stderr(
            f'Step 2 failed: {len(components)} component(s) have AND license expressions requiring '
            f'confirmation — configure in Hermine.\n'
            f'Link: {self.url}{link}'
        )
        return components

    def _handle_validation_3(self, response: Optional[dict]) -> list[dict]:
        """Step 3: Exploitation mode not defined for all scopes."""
        link = response.get('details', '') if response else ''
        unset_scopes = (response or {}).get('unset_scopes', [])
        self.print_stderr(
            f'Step 3 failed: {len(unset_scopes)} scope(s) are missing an exploitation mode definition — '
            f'configure in Hermine.\n'
            f'Link: {self.url}{link}'
        )
        parsed = []
        for entry in unset_scopes:
            try:
                project, scope, version_id = ast.literal_eval(entry)
                parsed.append({'project': project, 'scope': scope, 'component_count': version_id})
            except (ValueError, SyntaxError):
                parsed.append({'raw': entry})
        return parsed

    def _handle_validation_4(self, response: Optional[dict]) -> list[dict]:
        """Step 4: Unresolved license choices for this release."""
        link = response.get('details', '') if response else ''
        items = (response or {}).get('to_resolve', [])
        descriptions = '\n'.join(
            f'  - [{item.get("project", "")} / {item.get("scope", "")}] {item.get("description", "").strip()}'
            for item in items
        )
        self.print_stderr(
            f'Step 4 failed: {len(items)} component(s) have unresolved license choices — configure in Hermine.\n'
            f'Link: {self.url}{link}\n'
            f'{descriptions}'
        )
        return []

    def _format_validation_output(self, components: list[dict], link: str) -> str:
        """Format validation failure components according to the current format_type."""
        if not components:
            return ''
        if self.format_type == 'jira_md':
            headers = list(components[0].keys())
            rows = [[str(item.get(h, '')) for h in headers] for item in components]
            return (
                f'h3. Hermine: Action Required\n{generate_jira_table(headers, rows, [])}\n'
                f'Configure in Hermine [here|{self.url}{link}].\n'
            )
        if self.format_type == 'md':
            headers = list(components[0].keys())
            rows = [[str(item.get(h, '')) for h in headers] for item in components]
            return (
                f'### Hermine: Action Required\n{generate_table(headers, rows, [])}\n'
                f'Configure in Hermine [here]({self.url}{link}).\n'
            )
        return json.dumps(components, indent=2)

    def release_validation(self) -> tuple[bool, list[dict], str]:
        """
        Run validations 1-4. Returns (True, [], '') if all pass, or (False, components, link) on first failure.
        """
        handlers = [
            (1, self._handle_validation_1),
            (2, self._handle_validation_2),
            (3, self._handle_validation_3),
            (4, self._handle_validation_4),
        ]
        for i, handler in handlers:
            response = self.hm_service.get_hermine_data(f'{self.url}/api/releases/{self.release_id}/validation_{i}')
            if response is None or not response.get('valid', False):
                link = response.get('details', '') if response else ''
                return False, handler(response), link
        return True, [], ''

    def _handle_validation_6(self, response: Optional[dict], version_purl_map: dict) -> tuple[list[dict], str]:
        """Step 6: Check license compatibility. Returns (violations, link)."""
        link = response.get('details', '') if response else ''
        lic_by_spdx = {lic['spdx_id']: lic for lic in (response or {}).get('incompatible_licenses', [])}
        violations = [
            {
                'purl': version_purl_map.get(usage.get('version'), ''),
                'license_expression': usage.get('license_expression', ''),
                'scope': usage.get('scope', ''),
                'project': usage.get('project', ''),
                'exploitation': usage.get('exploitation', ''),
                'licenses': [
                    {
                        'spdx_id': lic['spdx_id'],
                        'copyleft': lic.get('copyleft'),
                        'osi_approved': lic.get('osi_approved'),
                    }
                    for spdx_id, lic in lic_by_spdx.items()
                    if spdx_id in self._spdx_tokens(usage.get('license_expression', ''))
                ],
            }
            for usage in (response or {}).get('incompatible_usages', [])
        ]
        return violations, link

    @staticmethod
    def _spdx_tokens(expr: str) -> set[str]:
        """Split an SPDX expression into individual license identifiers."""
        tokens = re.split(r'\s+(?:AND|OR|WITH)\s+|\s+', expr.strip())
        return {token.strip('()') for token in tokens} - {'', '+'}

    def _handle_validation_5(
            self, response: Optional[dict], version_purl_map: dict
    ) -> tuple[list[dict], list[dict]]:
        """Step 5: Check licenses against policy.

        Returns (never_allowed, context_allowed) after derogation filtering.
        """
        lic_by_spdx = {lic['spdx_id']: lic for lic in (response or {}).get('involved_lic', [])}
        derogated = {(d['version'], d['license']) for d in (response or {}).get('derogations', [])}

        def matched_lics(expr: str) -> list[dict]:
            tokens = self._spdx_tokens(expr)
            return [lic for spdx_id, lic in lic_by_spdx.items() if spdx_id in tokens]

        def is_exempt(usage: dict) -> bool:
            version_id = usage.get('version')
            lics = matched_lics(usage.get('license_expression', ''))
            return any((version_id, lic['id']) in derogated for lic in lics)

        def format_usage(usage: dict) -> dict:
            expr = usage.get('license_expression', '')
            return {
                'purl': version_purl_map.get(usage.get('version'), ''),
                'license_expression': expr,
                'scope': usage.get('scope', ''),
                'project': usage.get('project', ''),
                'exploitation': usage.get('exploitation', ''),
                'licenses': [
                    {
                        'spdx_id': lic['spdx_id'],
                        'copyleft': lic.get('copyleft'),
                        'osi_approved': lic.get('osi_approved'),
                    }
                    for lic in matched_lics(expr)
                ],
            }

        never_allowed = [
            format_usage(u) for u in (response or {}).get('usages_lic_never_allowed', []) if not is_exempt(u)
        ]
        context_allowed = [
            format_usage(u) for u in (response or {}).get('usages_lic_context_allowed', []) if not is_exempt(u)
        ]
        return never_allowed, context_allowed

    def release_violations(self) -> int:
        """
        Validations 5 and 6
        """
        version_purl_map = self.hm_service.get_version_purl_map()

        response_5 = self.hm_service.get_hermine_data(f'{self.url}/api/releases/{self.release_id}/validation_5')
        if response_5 is None or not response_5.get('valid', False):
            never_allowed, context_allowed = self._handle_validation_5(response_5, version_purl_map)
            link = response_5.get('details', '') if response_5 else ''
            self.print_stderr(
                f'Step 5 failed: {len(never_allowed)} never-allowed, {len(context_allowed)} context-conditional.\n'
                f'Link: {self.url}{link}'
            )
            flat = (
                [{**v, 'category': 'Never Allowed'} for v in never_allowed] +
                [{**v, 'category': 'Context Allowed'} for v in context_allowed]
            )
            status, _ = self._generate_formatter_report(flat)
            return status

        response_6 = self.hm_service.get_hermine_data(f'{self.url}/api/releases/{self.release_id}/validation_6')
        if response_6 is None or not response_6.get('valid', False):
            violations, link = self._handle_validation_6(response_6, version_purl_map)
            self.print_stderr(
                f'Step 6 failed: {len(violations)} incompatible license combination(s) found.\n'
                f'Link: {self.url}{link}'
            )
            flat = [{**v, 'category': 'Incompatible'} for v in violations]
            status, _ = self._generate_formatter_report(flat)
            return status

        return PolicyStatus.POLICY_SUCCESS.value



    def run(self) -> int:
        """
        Run the Hermine violations policy check.

        Returns:
            int: PolicyStatus value — SUCCESS (0), FAIL (2), or ERROR (1)
        """
        if self.product_id is None and self.release_id is None:
            result = self.hm_service.get_ids(self.product_name, self.release_name)
            if not result:
                self.print_stderr('Failed to get ids.')
                return PolicyStatus.ERROR.value
            self.product_id, self.release_id = result
        if self.debug:
            self.print_msg(f'URL: {self.url}')
            self.print_msg(f'Product Id: {self.product_id}')
            self.print_msg(f'Product Name: {self.product_name}')
            self.print_msg(f'Release Id: {self.release_id}')
            self.print_msg(f'Release Name: {self.release_name}')
            self.print_msg(f'API Key: {"*" * len(self.api_key)}')
            self.print_msg(f'Format: {self.format_type}')
            self.print_msg(f'Status: {self.status}')
            self.print_msg(f'Output: {self.output}')
            self.print_msg(f'Timeout: {self.timeout}')
        valid, components, link = self.release_validation()
        if not valid:
            if components:
                self.print_to_file_or_stdout(self._format_validation_output(components, link), self.output)
            return PolicyStatus.POLICY_FAIL.value
        return self.release_violations()



