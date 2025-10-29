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
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, TypedDict

from ....services.dependency_track_service import DependencyTrackService
from ...utils.markdown_utils import generate_jira_table, generate_table
from ..policy_check import PolicyCheck, PolicyOutput, PolicyStatus

# Constants
PROCESSING_RETRY_DELAY = 5  # seconds
DEFAULT_TIME_OUT = 300.0
MILLISECONDS_TO_SECONDS = 1000

"""
Dependency Track project violation policy check implementation.

This module provides policy checking functionality for Dependency Track project violations.
It retrieves, processes, and formats policy violations from a Dependency Track instance
for a specific project.
"""


class ResolvedLicenseDict(TypedDict):
    """TypedDict for resolved license information from Dependency Track."""
    uuid: str
    name: str
    licenseId: str
    isOsiApproved: bool
    isFsfLibre: bool
    isDeprecatedLicenseId: bool
    isCustomLicense: bool


class ProjectDict(TypedDict):
    """TypedDict for project information from Dependency Track."""
    authors: List[str]
    name: str
    version: str
    classifier: str
    collectionLogic: str
    uuid: str
    properties: List[Any]
    tags: List[str]
    lastBomImport: int
    lastBomImportFormat: str
    lastInheritedRiskScore: float
    lastVulnerabilityAnalysis: int
    active: bool
    isLatest: bool


class ComponentDict(TypedDict):
    """TypedDict for component information from Dependency Track."""
    authors: List[str]
    name: str
    version: str
    classifier: str
    purl: str
    purlCoordinates: str
    resolvedLicense: ResolvedLicenseDict
    project: ProjectDict
    lastInheritedRiskScore: float
    uuid: str
    expandDependencyGraph: bool
    isInternal: bool
    cpe: Optional[str]


class PolicyDict(TypedDict):
    """TypedDict for policy information from Dependency Track."""
    name: str
    operator: str
    violationState: str
    uuid: str
    includeChildren: bool
    onlyLatestProjectVersion: bool


class PolicyConditionDict(TypedDict):
    """TypedDict for policy condition information from Dependency Track."""
    policy: PolicyDict
    operator: str
    subject: str
    value: str
    uuid: str


class PolicyViolationDict(TypedDict):
    """TypedDict for policy violation information from Dependency Track."""
    type: str
    project: ProjectDict
    component: ComponentDict
    policyCondition: PolicyConditionDict
    timestamp: int
    uuid: str


class DependencyTrackProjectViolationPolicyCheck(PolicyCheck[PolicyViolationDict]):
    """
    Policy check implementation for Dependency Track project violations.
    
    This class handles retrieving, processing, and formatting policy violations
    from a Dependency Track instance for a specific project.
    """

    def __init__(  # noqa: PLR0913
            self,
            debug: bool = False,
            trace: bool = False,
            quiet: bool = False,
            project_id: str = None,
            project_name: str = None,
            project_version: str = None,
            api_key: str = None,
            url: str = None,
            upload_token: str = None,
            timeout: float = DEFAULT_TIME_OUT,
            format_type: str = None,
            status: str = None,
            output: str = None,
    ):
        """
        Initialise the Dependency Track project violation policy checker.
        
        Args:
            debug: Enable debug output
            trace: Enable trace output
            quiet: Enable quiet mode
            project_id: UUID of the project in Dependency Track
            project_name: Name of the project in Dependency Track
            project_version: Version of the project in Dependency Track
            api_key: API key for Dependency Track authentication
            url: Base URL of the Dependency Track instance
            upload_token: Upload token for uploading BOMs to Dependency Track
            format_type: Output format type (json, markdown, etc.)
            status: Status output destination
            output: Results output destination
            timeout: Timeout for processing in seconds (default: 300)
        """
        super().__init__(debug, trace, quiet, format_type, status, 'dependency-track', output)
        self.api_key = api_key
        self.project_id = project_id
        self.project_name = project_name
        self.project_version = project_version
        self.upload_token = upload_token
        self.timeout = timeout
        self.url = url.strip().rstrip('/') if url else None
        self.dep_track_service = DependencyTrackService(self.api_key, self.url, debug=debug, trace=trace, quiet=quiet)

    def _json(self, project_violations: list[PolicyViolationDict]) -> PolicyOutput:
        """
        Format project violations as JSON.
        
        Args:
            project_violations: List of policy violations from Dependency Track
            
        Returns:
            Dictionary containing JSON formatted results and summary
        """
        return PolicyOutput(
            details= json.dumps(project_violations, indent=2),
            summary= f'{len(project_violations)} policy violations were found.\n',
        )

    def _markdown(self, project_violations: list[PolicyViolationDict]) -> PolicyOutput:
        """
        Format Dependency Track violations to Markdown format.
        
        Args:
            project_violations: List of policy violations from Dependency Track
            
        Returns:
            Dictionary with formatted Markdown details and summary
        """
        return self._md_summary_generator(project_violations, generate_table)

    def _jira_markdown(self, data: list[PolicyViolationDict]) -> PolicyOutput:
        """
        Format project violations for Jira Markdown.
        
        Args:
            data: List of policy violations from Dependency Track
            
        Returns:
            Dictionary containing Jira markdown formatted results and summary
        """
        return self._md_summary_generator(data, generate_jira_table)

    def is_project_updated(self, dt_project: Dict[str, Any]) -> bool:
        """
        Check if a Dependency Track project has completed processing.
        
        This method determines if a project has finished processing by comparing
        the timestamps of the last BOM import, vulnerability analysis, and last
        occurrence metrics. A project is considered updated when either the
        vulnerability analysis or the metrics' last occurrence timestamp is greater
        than or equal to the last BOM import timestamp.
        
        Args:
            dt_project: Project dictionary from Dependency Track containing
                       project metadata and timestamps
                       
        Returns:
            True if the project has completed processing (vulnerability analysis
            or metrics are up to date with the last BOM import), False otherwise
        """
        if not dt_project:
            self.print_stderr('Warning: No project details supplied. Returning False.')
            return False

        # Safely extract and normalise timestamp values to numeric types
        def _safe_timestamp(field, value=None, default=0) -> float:
            """Convert timestamp value to float, handling string/numeric types safely."""
            if value is None:
                return float(default)
            try:
                return float(value)
            except (ValueError, TypeError):
                self.print_stderr(f'Warning: Invalid timestamp for {field}, value: {value}, using default: {default}')
                return float(default)

        last_import = _safe_timestamp('lastBomImport', dt_project.get('lastBomImport'), 0)
        last_vulnerability_analysis = _safe_timestamp('lastVulnerabilityAnalysis',
                                                      dt_project.get('lastVulnerabilityAnalysis'), 0
                                                      )
        metrics = dt_project.get('metrics', {})
        last_occurrence = _safe_timestamp('lastOccurrence',
                                          metrics.get('lastOccurrence', 0)
                                          if isinstance(metrics, dict) else 0, 0
                                          )
        if self.debug:
            self.print_msg(f'last_import: {last_import}')
            self.print_msg(f'last_vulnerability_analysis: {last_vulnerability_analysis}')
            self.print_msg(f'last_occurrence: {last_occurrence}')
            self.print_msg(f'last_vulnerability_analysis is updated: {last_vulnerability_analysis >= last_import}')
            self.print_msg(f'last_occurrence is updated: {last_occurrence >= last_import}')
        # Catches case where vulnerability analysis is skipped for empty SBOMs
        if 0 < last_import <= last_occurrence:
            component_count = metrics.get('components', 0) if isinstance(metrics, dict) else 0
            if component_count < 1:
                self.print_msg('Notice: Empty SBOM detected. Assuming no violations.')
                return True
        # If all timestamps are zero, this indicates no processing has occurred
        if last_vulnerability_analysis == 0 or last_occurrence == 0 or last_import == 0:
            self.print_stderr(f'Warning: Some project data appears to be unset. Returning False: {dt_project}')
            return False
        # True if: Both vulnerability analysis and metrics calculation newer than last BOM upload
        return last_vulnerability_analysis >= last_import and last_occurrence >= last_import

    def _wait_processing_by_project_id(self) -> Optional[Any] or None:
        """
                Wait for project processing to complete in Dependency Track.

                Returns:
                    Return the project or None if processing fails or times out
        """
        start_time = time.time()
        while True:
            self.print_debug('Starting...')
            dt_project = self.dep_track_service.get_project_by_id(self.project_id)
            if not dt_project:
                self.print_stderr(f'Failed to get project by id: {self.project_id}')
                return None
            is_project_updated = self.is_project_updated(dt_project)
            if is_project_updated:  # Project updated, return it
                return dt_project
            # Check timeout
            if time.time() - start_time > self.timeout:
                self.print_msg(f'Warning: Timeout reached ({self.timeout}s) while waiting for project processing')
                return dt_project
            time.sleep(PROCESSING_RETRY_DELAY)
            self.print_debug('Checking if complete...')
        # End while loop

    def _wait_processing_by_project_status(self):
        """
        Wait for project processing to complete in Dependency Track.

        Returns:
            Project status dictionary or None if processing fails or times out
        """
        start_time = time.time()
        while True:
            status = self.dep_track_service.get_project_status(self.upload_token)
            if status is None:
                self.print_stderr(f'Error getting project status for upload token: {self.upload_token}')
                break
            if status and not status.get('processing'):
                self.print_debug(f'Project Status: {status}')
                break
            if time.time() - start_time > self.timeout:
                self.print_msg(f'Timeout reached ({self.timeout}s) while waiting for project processing')
                break
            time.sleep(PROCESSING_RETRY_DELAY)
            self.print_debug('Checking if complete...')
        # End while loop

    def _wait_project_processing(self):
        """
        Wait for project processing to complete in Dependency Track.
        
        Returns:
            Project status dictionary or None if processing fails
        """
        if self.upload_token:
            self.print_debug("Using upload token to check project status")
            self._wait_processing_by_project_status()
        self.print_debug("Using project id to get project status")
        return self._wait_processing_by_project_id()

    def _set_project_id(self) -> None:
        """
        Set the project ID based on the project name and version if not already set.
        If no project id is specified, this method will attempt to retrieve the project based on name/version.
        
        Raises:
            ValueError: If the project name/version is missing or the project is not found.
            RuntimeError: If there's an error communicating with Dependency Track.
        """
        if self.project_id is not None:
            return
        if self.project_name is None or self.project_version is None:
            raise ValueError(
                "Error: Project name and version must be specified when not using project ID"
            )
        self.print_debug(f'Searching for project id by name and version: {self.project_name}@{self.project_version}')
        dt_project = self.dep_track_service.get_project_by_name_version(self.project_name, self.project_version)
        self.print_debug(f'dt_project: {dt_project}')
        if dt_project is None:
            raise ValueError(f'Error: Project {self.project_name}@{self.project_version} not found in Dependency Track')
        self.project_id = dt_project.get('uuid')
        if not self.project_id:
            self.print_stderr(f'Error: Failed to get project uuid from: {dt_project}')
            raise ValueError(f'Error: Project {self.project_name}@{self.project_version} does not have a valid UUID')

    def _sort_project_violations(self,violations: List[PolicyViolationDict]) -> List[PolicyViolationDict]:
        """
        Sort project violations by priority.
        
        Sorts violations with SECURITY issues first, followed by LICENSE,
        then OTHER types.
        
        Args:
            violations: List of policy violation dictionaries
            
        Returns:
            Sorted list of policy violations
        """
        type_priority = {'SECURITY': 3, 'LICENSE': 2, 'OTHER': 1}
        return sorted(
            violations,
            key=lambda x: -type_priority.get(x.get('type', 'OTHER'), 1)
        )

    def _md_summary_generator(self, project_violations: list[PolicyViolationDict], table_generator) -> PolicyOutput:
        """
        Generates a Markdown summary of project policy violations.

        Args:
            project_violations (list[PolicyViolationDict]): A list of dictionaries containing details of
                project policy violations, including violation state, risk type, policy name, component details,
                and timestamp.
            table_generator (function): A callable function responsible for generating the Markdown table
                using headers, rows, and optionally highlighted columns.

        Returns:
            dict: A dictionary with two keys:
                - "details" containing a Markdown-compatible string with detailed project violations
                  rendered as a table
                - "summary" summarising the number of violations found
        """
        if project_violations is None:
            self.print_stderr('Warning: No project violations found. Returning empty results.')
            return PolicyOutput(
                details= "h3. Dependency Track Project Violations\n\nNo policy violations found.\n",
                summary= "0 policy violations were found.\n",
            )
        headers = ['State', 'Risk Type', 'Policy Name', 'Component', 'Date']
        c_cols = [0, 1]
        rows: List[List[str]] = []

        for project_violation in project_violations:
            timestamp = project_violation['timestamp']
            timestamp_seconds = timestamp / MILLISECONDS_TO_SECONDS
            formatted_date = datetime.fromtimestamp(timestamp_seconds).strftime("%d %b %Y at %H:%M:%S")

            purl = project_violation["component"]["purl"]
            version = project_violation["component"]["version"]
            # If PURL doesn't contain version but version is available, append it
            component_display = purl
            if version and '@' not in purl:
                component_display = f'{purl}@{version}'
            row = [
                project_violation['policyCondition']["policy"]["violationState"],
                project_violation['type'],
                project_violation['policyCondition']["policy"]["name"],
                component_display,
                formatted_date,
            ]
            rows.append(row)
        # End for loop
        return PolicyOutput(
            details= f'### Dependency Track Project Violations\n{table_generator(headers, rows, c_cols)}\n\n'
                       f'View project in Dependency Track [here]({self.url}/projects/{self.project_id}).\n',
            summary= f'{len(project_violations)} policy violations were found.\n'
        )

    def run(self) -> int:
        """
        Runs the primary execution logic of the instance.

        Returns:
            int: Status code indicating the result of the run process. Possible
            values are derived from the PolicyStatus enumeration.
            FAIL if violations are found, SUCCESS if no violations are found, ERROR if an error occurs.

        Raises:
            ValueError: If an invalid format is specified during the execution.
        """
        # Set project ID based on name/version if needed
        self._set_project_id()
        if self.debug:
            self.print_msg(f'URL: {self.url}')
            self.print_msg(f'Project Id: {self.project_id}')
            self.print_msg(f'Project Name: {self.project_name}')
            self.print_msg(f'Project Version: {self.project_version}')
            self.print_msg(f'API Key: {"*" * len(self.api_key)}')
            self.print_msg(f'Format: {self.format_type}')
            self.print_msg(f'Status: {self.status}')
            self.print_msg(f'Output: {self.output}')
            self.print_msg(f'Timeout: {self.timeout}')
        # Confirm processing is complete before returning project violations
        dt_project = self._wait_project_processing()
        if not dt_project:
            return PolicyStatus.ERROR.value
        # Get project violations from Dependency Track
        dt_project_violations = self.dep_track_service.get_project_violations(self.project_id)
        # Handle case where service returns None (API error) vs empty list (no violations)
        if dt_project_violations is None:
            self.print_stderr('Error: Failed to retrieve project violations from Dependency Track')
            return PolicyStatus.ERROR.value
        # Sort violations by priority and format output
        formatter = self._get_formatter()
        if formatter is None:
            self.print_stderr('Error: Invalid format specified.')
            return PolicyStatus.ERROR.value
        # Format and output data - handle empty results gracefully
        policy_output = formatter(self._sort_project_violations(dt_project_violations))
        self.print_to_file_or_stdout(policy_output.details, self.output)
        self.print_to_file_or_stderr(policy_output.summary, self.status)
        # Return appropriate status based on violation count
        if len(dt_project_violations) > 0:
            return PolicyStatus.POLICY_FAIL.value
        return PolicyStatus.POLICY_SUCCESS.value

