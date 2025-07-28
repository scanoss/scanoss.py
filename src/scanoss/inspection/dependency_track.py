from typing import Dict, Any
import requests
from .policy_check import PolicyCheck

class DependencyTrackPolicyCheck(PolicyCheck):
    def __init__(  # noqa: PLR0913
            self,
            debug: bool = False,
            trace: bool = False,
            quiet: bool = False,
            dependency_track_project_id: str = None,
            dependency_track_api_key: str = None,
            dependency_track_url: str = None,
            dependency_track_project_name: str = None,
            dependency_track_project_version: str = None,
            format_type: str = None,
            status: str = None,
            output: str = None,
    ):
        super().__init__(debug, trace, quiet, format_type,status, 'dependency-track', output)
        self.dependency_track_url = dependency_track_url
        self.dependency_track_api_key = dependency_track_api_key
        self.dependency_track_project_id = dependency_track_project_id
        self.dependency_track_project_name = dependency_track_project_name
        self.dependency_track_project_version = dependency_track_project_version

    def _json(self, components: list) -> Dict[str, Any]:
        pass

    def _markdown(self, components: list) -> Dict[str, Any]:
        pass
    def _jira_markdown(self, components: list) -> Dict[str, Any]:
        pass


    def _get_project_by_id(self):
        """Get project by ID"""
        url = f"{self.dependency_track_url}/api/v1/project/{self.dependency_track_project_id}"
        req_headers = {'X-Api-Key': self.dependency_track_api_key, 'Content-Type': 'application/json'}
        try:
            response = requests.get(url, headers=req_headers)
            response.raise_for_status()  # Raises an HTTPError for bad responses

            return response.json()

        except requests.exceptions.RequestException as e:
            print(f"Error calling API: {e}")
            return None

    def _get_project_by_name_and_version(self):
        """Lookup project by name and version"""
        url = f"{self.dependency_track_url}/api/v1/project/lookup"
        req_headers = { 'X-Api-Key': self.dependency_track_api_key, 'Content-Type': 'application/json' }
        params = {
            "name": self.dependency_track_project_name,
            "version": self.dependency_track_project_version
        }
        try:
            response = requests.get(url, headers=req_headers, params=params)
            response.raise_for_status()

            return response.json()

        except requests.exceptions.RequestException as e:
            print(f"Error calling API: {e}")
            return None

    def _get_project_data(self):
        if self.dependency_track_project_id:
            return self._get_project_by_id()
        elif self.dependency_track_project_name and self.dependency_track_project_version:
            return self._get_project_by_name_and_version()
        else:
            self.print_stderr("ERROR: Either provide 'Dependency Track project ID' OR both 'Dependency Track project name' and 'Dependency Track project version")
            return None

    def run(self):
        print("Running Dependency Track Policy Check")
        dep_track_project_data = self._get_project_data()
        print("Dependency track project data: ", dep_track_project_data)

