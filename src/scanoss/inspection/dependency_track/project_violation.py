import json
import time
from datetime import datetime
from typing import Dict, Any, Optional, List, TypedDict
import requests

from ..policy_check import PolicyCheck, PolicyStatus


class ResolvedLicenseDict(TypedDict):
    uuid: str
    name: str
    licenseId: str
    isOsiApproved: bool
    isFsfLibre: bool
    isDeprecatedLicenseId: bool
    isCustomLicense: bool

class ProjectDict(TypedDict):
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
    name: str
    operator: str
    violationState: str
    uuid: str
    includeChildren: bool
    onlyLatestProjectVersion: bool

class PolicyConditionDict(TypedDict):
    policy: PolicyDict
    operator: str
    subject: str
    value: str
    uuid: str

class PolicyViolationDict(TypedDict):
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
            dependency_track_api_key: str = None,
            dependency_track_url: str = None,
            dependency_track_upload_token: str = None,
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
            dependency_track_api_key: API key for Dependency Track authentication
            dependency_track_url: Base URL of the Dependency Track instance
            dependency_track_upload_token: Token for tracking upload processing status
            format_type: Output format type (json, markdown, etc.)
            status: Status output destination
            output: Results output destination
        """
        super().__init__(debug, trace, quiet, format_type, status, 'dependency-track', output)
        self.dependency_track_url = dependency_track_url
        self.dependency_track_api_key = dependency_track_api_key
        self.dependency_track_project_id = dependency_track_project_id
        self.dependency_track_upload_token = dependency_track_upload_token

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
        Format Dependency Track Violations to Markdown format.

        :param project_violations: Dependency track project_violations
        :return: Dictionary with formatted Markdown details and summary
        """
        headers = ['State', 'Risk Type', 'Policy Name', 'Component', 'Date']
        centered_columns = [0,1]
        rows: [[]] = []
        for project_violation in project_violations:
                timestamp = project_violation['timestamp']
                timestamp_seconds = timestamp / 1000  # Convert to seconds
                formatted_date = datetime.fromtimestamp(timestamp_seconds).strftime("%d %b %Y at %H:%M:%S")

                row = [
                    project_violation['policyCondition']["policy"]["violationState"],
                    project_violation['type'],
                    project_violation['policyCondition']["policy"]["name"],
                    f'{project_violation["component"]["purl"]}@{project_violation["component"]["version"]}',
                    formatted_date,
                ]
                rows.append(row)
            # End license loop
        # End component loop
        return {
            "details": self.generate_table(headers, rows, centered_columns),
            "summary": f"{len(project_violations)} policy violations were found.\n",
        }

    def _jira_markdown(self, data: list[PolicyViolationDict]) -> Dict[str, Any]:
        """
        Format project violations for Jira markdown.
        
        Args:
            data: List of policy violations from Dependency Track
            
        Returns:
            Dictionary containing Jira markdown formatted results and summary
            
        Note:
            This method is not implemented yet.
        """
        pass


    def _get_project_status(self):
        """
        Get Dependency Track project processing status.
        
        Queries the Dependency Track API to check if the project upload
        processing is complete using the upload token.
        
        Returns:
            dict: Project status information or None if request fails
        """
        url = f"{self.dependency_track_url}/api/v1/event/token/{self.dependency_track_upload_token}"
        req_headers = {'X-Api-Key': self.dependency_track_api_key, 'Content-Type': 'application/json'}
        try:
            response = requests.get(url, headers=req_headers)
            response.raise_for_status()  # Raises an HTTPError for bad responses

            return response.json()

        except requests.exceptions.RequestException as e:
            print(f"Error calling API: {e}")
            return None

    def _get_dependency_track_project_violations(self):
        """
        Get project violations from Dependency Track.
        
        Waits for project processing to complete, then retrieves all policy
        violations for the specified project ID.
        
        Returns:
            list: List of policy violations or None if request fails
        """
        status = self._get_project_status()
        max_tries = 10
        while status['processing'] == True and max_tries>0:
            max_tries = max_tries - 1
            time.sleep(1)
            status = self._get_project_status()
        url = f"{self.dependency_track_url}/api/v1/violation/project/{self.dependency_track_project_id}"
        req_headers = {'X-Api-Key': self.dependency_track_api_key, 'Content-Type': 'application/json'}
        try:
            response = requests.get(url, headers=req_headers)
            response.raise_for_status()  # Raises an HTTPError for bad responses

            return response.json()

        except requests.exceptions.RequestException as e:
            print(f"Error calling API: {e}")
            return None

    def _sort_project_violations(self, violations):
        """
        Sort project violations by priority.
        
        Sorts violations with SECURITY issues first, followed by LICENSE,
        then OTHER types.
        
        Args:
            violations: List of policy violation dictionaries
            
        Returns:
            list: Sorted list of policy violations
        """
        type_priority = {'SECURITY': 3, 'LICENSE': 2, 'OTHER': 1}
        return sorted(violations, key=lambda x: (
            -type_priority.get(x.get('type', 'OTHER'), 1),  # First: type priority
        ))

    def run(self):
        """
        Execute the policy check for Dependency Track project violations.
        
        Retrieves project violations from Dependency Track, sorts them by priority,
        formats the output according to the specified format, and outputs the results.
        
        Returns:
            tuple: (status_code, formatted_data) where status_code indicates
                   SUCCESS if violations found, FAIL if no violations, ERROR if failed
        """
        dep_track_project_violations = self._get_dependency_track_project_violations()
        sorted_project_violations = self._sort_project_violations(dep_track_project_violations)
        formatter = self._get_formatter()
        if formatter is None:
            return PolicyStatus.ERROR.value, {}
        # Format data
        data = formatter(sorted_project_violations)
        ## Save outputs if required
        self.print_to_file_or_stdout(data['details'], self.output)
        self.print_to_file_or_stderr(data['summary'], self.status)
        # Check to see if we have policy violations
        if len(dep_track_project_violations) <= 0:
            return PolicyStatus.FAIL.value, data
        return PolicyStatus.SUCCESS.value, data