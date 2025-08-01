"""Dependency Track project violation policy check implementation.

This module provides policy checking functionality for Dependency Track project violations.
It retrieves, processes, and formats policy violations from a Dependency Track instance
for a specific project.
"""

import json
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, TypedDict

import requests

from ...services.dependency_track_service import DependencyTrackService
from ..policy_check import PolicyCheck, PolicyStatus

# Constants
MAX_PROCESSING_RETRIES = 10
PROCESSING_RETRY_DELAY = 5  # seconds
DEFAULT_TIME_OUT = 3600
MILLISECONDS_TO_SECONDS = 1000


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
            dependency_track_project_id: str = None,
            dependency_track_project_name: str = None,
            dependency_track_project_version: str = None,
            dependency_track_api_key: str = None,
            dependency_track_url: str = None,
            dependency_track_upload_token: str = None,
            timeout: int = DEFAULT_TIME_OUT,
            format_type: str = None,
            status: str = None,
            output: str = None,
    ):
        """
        Initialize the Dependency Track project violation policy checker.
        
        Args:
            debug: Enable debug output
            trace: Enable trace output
            quiet: Enable quiet mode
            dependency_track_project_id: UUID of the project in Dependency Track
            dependency_track_project_name: Name of the project in Dependency Track
            dependency_track_project_version: Version of the project in Dependency Track
            dependency_track_api_key: API key for Dependency Track authentication
            dependency_track_url: Base URL of the Dependency Track instance
            dependency_track_upload_token: Upload token for uploading BOMs to Dependency Track
            format_type: Output format type (json, markdown, etc.)
            status: Status output destination
            output: Results output destination
            timeout: Timeout for processing in seconds (default: 5 seconds)
        """
        super().__init__(debug, trace, quiet, format_type, status, 'dependency-track', output)
        self.dependency_track_url = dependency_track_url
        self.dependency_track_api_key = dependency_track_api_key
        self.dependency_track_project_id = dependency_track_project_id
        self.dependency_track_project_name = dependency_track_project_name
        self.dependency_track_project_version = dependency_track_project_version
        self.dependency_track_upload_token = dependency_track_upload_token
        self.timeout = timeout
        self.dependency_track_service = DependencyTrackService(self.dependency_track_api_key,
                                                             self.dependency_track_url,
                                                             debug=debug,
                                                             trace=trace,
                                                             quiet=quiet)


    def _json(self, project_violations: list[PolicyViolationDict]) -> Dict[str, Any]:
        """
        Format project violations as JSON.
        
        Args:
            project_violations: List of policy violations from Dependency Track
            
        Returns:
            Dictionary containing JSON formatted results and summary
        """
        return {
            "details": json.dumps(project_violations, indent=2),
            "summary": f"{len(project_violations)} policy violations were found.\n",
        }

    def _markdown(self, project_violations: list[PolicyViolationDict]) -> Dict[str, Any]:
        """
        Format Dependency Track violations to Markdown format.
        
        Args:
            project_violations: List of policy violations from Dependency Track
            
        Returns:
            Dictionary with formatted Markdown details and summary
        """
        headers = ['State', 'Risk Type', 'Policy Name', 'Component', 'Date']
        c_cols = [0, 1]
        rows: List[List[str]] = []
        
        for project_violation in project_violations:
            timestamp = project_violation['timestamp']
            timestamp_seconds = timestamp / MILLISECONDS_TO_SECONDS
            formatted_date = datetime.fromtimestamp(timestamp_seconds).strftime("%d %b %Y at %H:%M:%S")

            row = [
                project_violation['policyCondition']["policy"]["violationState"],
                project_violation['type'],
                project_violation['policyCondition']["policy"]["name"],
                f'{project_violation["component"]["purl"]}@{project_violation["component"]["version"]}',
                formatted_date,
            ]
            rows.append(row)
            
        return {
            "details": f"### Dependency Track Project Violations\n{self.generate_table(headers,rows, c_cols)}\n",
            "summary": f"{len(project_violations)} policy violations were found.\n",
        }

    def _jira_markdown(self, data: list[PolicyViolationDict]) -> Dict[str, Any]:
        """
        Format project violations for Jira markdown.
        
        Args:
            data: List of policy violations from Dependency Track
            
        Returns:
            Dictionary containing Jira markdown formatted results and summary
        """
        if not data:
            return {
                "details": "h3. Dependency Track Project Violations\n\nNo policy violations found.\n",
                "summary": "0 policy violations were found.\n",
            }

        headers = ['State', 'Risk Type', 'Policy Name', 'Component', 'Date']
        c_cols = [0, 1]
        rows: List[List[str]] = []

        for project_violation in data:
            timestamp = project_violation['timestamp']
            timestamp_seconds = timestamp / MILLISECONDS_TO_SECONDS
            formatted_date = datetime.fromtimestamp(timestamp_seconds).strftime("%d %b %Y at %H:%M:%S")

            row = [
                project_violation['policyCondition']["policy"]["violationState"],
                project_violation['type'],
                project_violation['policyCondition']["policy"]["name"],
                f'{project_violation["component"]["purl"]}@{project_violation["component"]["version"]}',
                formatted_date,
            ]
            rows.append(row)
        
        return {
            "details": f"### Dependency Track Project Violations\n{self.generate_jira_table(headers, rows, c_cols)}\n",
            "summary": f"{len(data)} policy violations were found.\n",
        }

    def is_project_updated(self, dt_project: Dict[str, Any]) -> bool:
        """
        Check if a Dependency Track project has completed processing.
        
        This method determines if a project has finished processing by comparing
        the timestamps of the last BOM import, vulnerability analysis, and last
        occurrence metrics. A project is considered updated when either the
        vulnerability analysis or metrics last occurrence timestamp is greater
        than or equal to the last BOM import timestamp.
        
        Args:
            dt_project: Project dictionary from Dependency Track containing
                       project metadata and timestamps
                       
        Returns:
            True if the project has completed processing (vulnerability analysis
            or metrics are up-to-date with the last BOM import), False otherwise
        """
        last_import = dt_project.get('lastBomImport', 0)
        last_vulnerability_analysis = dt_project.get('lastVulnerabilityAnalysis', 0)
        metrics = dt_project.get('metrics', {})
        last_occurrence = metrics.get('lastOccurrence', 0) if isinstance(metrics, dict) else 0

        if self.debug:
            self.print_debug(f"last_import: {last_import}")
            self.print_debug(f"last_vulnerability_analysis: {last_vulnerability_analysis}")
            self.print_debug(f"last_occurrence: {last_occurrence}")
            self.print_debug(
                f"last_vulnerability_analysis is updated: {last_vulnerability_analysis >= last_import}"
            )
            self.print_debug(
                f"last_occurrence is updated: {last_occurrence >= last_import}"
            )
        return last_vulnerability_analysis >= last_import or last_occurrence >= last_import

    def _wait_processing_by_project_id(self):
        """
                Wait for project processing to complete in Dependency Track.

                Returns:
                    Return project or None if processing fails or times out
                """

        dt_project = self.dependency_track_service.get_project_by_id(project_id=self.dependency_track_project_id)
        is_project_updated = self.is_project_updated(dt_project)
        start_time = time.time()

        while not is_project_updated:
            # Check timeout
            if time.time() - start_time > self.timeout:
                self.print_debug(f"Timeout reached ({self.timeout}s) while waiting for project processing")
                return None

            time.sleep(PROCESSING_RETRY_DELAY)
            try:
                dt_project = self.dependency_track_service.get_project_by_id(
                    project_id=self.dependency_track_project_id)
                is_project_updated = self.is_project_updated(dt_project)
            except requests.exceptions.RequestException as e:
                raise ValueError(f"Error getting project status by project id from Dependency Track: {e}")
        return dt_project


    def _wait_processing_by_project_status(self):
        """
        Wait for project processing to complete in Dependency Track.

        Returns:
            Project status dictionary or None if processing fails or times out
        """

        status = self.dependency_track_service.get_project_status(
            upload_token=self.dependency_track_upload_token
        )

        if self.debug:
            self.print_debug(f"Project Status: {status}")

        start_time = time.time()
        while status and status.get('processing'):
            # Check timeout
            if time.time() - start_time > self.timeout:
                self.print_debug(f"Timeout reached ({self.timeout}s) while waiting for project processing")
                return None

            time.sleep(PROCESSING_RETRY_DELAY)
            try:
                status = self.dependency_track_service.get_project_status(
                    upload_token=self.dependency_track_upload_token)
            except requests.exceptions.RequestException as e:
                raise ValueError(f"Error getting project status: {e}")
        return status

    def _wait_project_processing(self):
        """
        Wait for project processing to complete in Dependency Track.
        
        Returns:
            Project status dictionary or None if processing fails
        """
        if self.dependency_track_upload_token:
            if self.debug:
                self.print_debug("Using upload token to get project status")
            self._wait_processing_by_project_status()
        else:
            if self.debug:
                self.print_debug("Using project id to get project status")
            self._wait_processing_by_project_id()


    def _set_project_id(self) -> None:
        """
        Set the project ID based on project name and version if not already set.
        
        Raises:
            ValueError: If project name/version are missing or project not found
            RuntimeError: If there's an error communicating with Dependency Track
        """
        if self.dependency_track_project_id is not None:
            return
            
        if self.dependency_track_project_name is None or self.dependency_track_project_version is None:
            raise ValueError(
                "Error: Project name and version must be specified when not using project ID"
            )
            
        try:
            dt_project = self.dependency_track_service.get_project_by_name_version(
                self.dependency_track_project_name, 
                self.dependency_track_project_version
            )
            self.print_debug(f"dt_project: {dt_project}")
            
            if dt_project is None:
                raise ValueError(
                    f"Error: Project {self.dependency_track_project_name}@{self.dependency_track_project_version}"
                    f" not found in Dependency Track"
                )
                
            self.dependency_track_project_id = dt_project.get("uuid")
        except requests.exceptions.RequestException as e:
            raise ValueError(f"Error: Error getting project id from Dependency Track: {e}") from e

    def _get_dependency_track_project_violations(self) -> Optional[List[PolicyViolationDict]]:
        """
        Get project violations from Dependency Track.
        
        Waits for project processing to complete, then retrieves all policy
        violations for the specified project ID.
        
        Returns:
            List of policy violations or None if request fails
        """
        try:
            return self.dependency_track_service.get_project_violations(self.dependency_track_project_id)
        except requests.exceptions.RequestException as e:
            raise ValueError(f"Error: Error retrieving project violations from Dependency Track: {e}") from e


    @staticmethod
    def _sort_project_violations(violations: List[PolicyViolationDict]) -> List[PolicyViolationDict]:
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

    def run(self) -> tuple[int, Optional[Dict[str, Any]]]:
        """
        Execute the policy check for Dependency Track project violations.
        
        Retrieves project violations from Dependency Track, sorts them by priority,
        formats the output according to the specified format, and outputs the results.
        
        Returns:
            Tuple of (status_code, formatted_data) where status_code indicates:
                SUCCESS if violations found, FAIL if no violations, ERROR if failed
        """
        # Set project ID based on name/version if needed
        self._set_project_id()

        if self.debug:
            self.print_debug(f'URL: {self.dependency_track_url}')
            self.print_debug(f'Project Id: {self.dependency_track_project_id}')
            self.print_debug(f'Project Name: {self.dependency_track_project_name}')
            self.print_debug(f'Project Version: {self.dependency_track_project_version}')
            self.print_debug(f'API Key: {"*" * len(self.dependency_track_api_key)}')
            self.print_debug(f'Format: {self.format_type}')
            self.print_debug(f'Status: {self.status}')
            self.print_debug(f'Output: {self.output}')
            self.print_debug(f'Timeout: {self.timeout}')

        self._wait_project_processing()

        # Check if the project was processed
        dt_project = self.dependency_track_service.get_project_by_id(self.dependency_track_project_id)
        if not self.is_project_updated(dt_project):
            raise ValueError(
                f'Error: Project {self.dependency_track_project_id} is still processing project violations')

        # Get project violations from Dependency Track
        dep_track_project_violations = self._get_dependency_track_project_violations()

        # Sort violations by priority and format output
        sorted_project_violations = self._sort_project_violations(dep_track_project_violations)
        formatter = self._get_formatter()
        if formatter is None:
            return PolicyStatus.ERROR.value, {}

        # Format and output data
        data = formatter(sorted_project_violations)
        self.print_to_file_or_stdout(data['details'], self.output)
        self.print_to_file_or_stderr(data['summary'], self.status)

        # Return appropriate status based on violation count
        if len(dep_track_project_violations) == 0:
            return PolicyStatus.POLICY_FAIL.value, data
        return PolicyStatus.POLICY_SUCCESS.value, data
