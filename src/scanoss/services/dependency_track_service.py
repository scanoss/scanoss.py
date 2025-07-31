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

import requests

from ..scanossbase import ScanossBase

HTTP_OK = 200

class DependencyTrackService(ScanossBase):

    def __init__(
            self,
            api_key: str,
            url: str,
            debug: bool = False,
            trace: bool = False,
            quiet: bool = False,
    ):
        super().__init__(debug=debug, trace=trace, quiet=quiet)
        if not url:
            raise ValueError("Dependency Track URL is required")
        self.url = url.rstrip('/')
        if not api_key:
            raise ValueError("Dependency Track API key is required")
        self.api_key = api_key

    def get_project_by_name_version(self, name, version):
        """
        Get project information by name and version from Dependency Track

        Args:
            name: Project name to search for
            version: Project version to search for

        Returns:
            dict: Project data if found, None otherwise
        """
        try:
            if not name or not version:
                raise ValueError("Invalid name or version")

            # Use the project search endpoint
            params = {
                'name': name,
                'version': version
            }

            if self.trace:
                self.print_trace(f'URL: {self.url}')
                self.print_trace(f'Params: {params}')

            project_response = requests.get(
                f"{self.url}/api/v1/project/lookup",
                headers={"X-API-Key": self.api_key, "Content-Type": "application/json"},
                params=params
            )

            if project_response.status_code == HTTP_OK:
                project_data = project_response.json()
                return project_data

        except Exception as e:
            self.print_stderr(f"Error looking up project: {e}")
            return None


    def get_project_status(self, upload_token):
        """
        Get Dependency Track project processing status.

        Queries the Dependency Track API to check if the project upload
        processing is complete using the upload token.

        Returns:
            dict: Project status information or None if request fails
        """

        if self.trace:
            self.print_trace(f'URL: {self.url}')
            self.print_trace(f'Upload token: {upload_token}')

        url = f"{self.url}/api/v1/event/token/{upload_token}"
        req_headers = {'X-Api-Key': self.api_key, 'Content-Type': 'application/json'}
        try:
            response = requests.get(url, headers=req_headers)
            response.raise_for_status()  # Raises an HTTPError for bad responses

            return response.json()

        except requests.exceptions.RequestException as e:
            self.print_stderr(f"Error getting project status: {e}")
            return None

    def get_project_violations(self,project_id:str):
        """
        Get project violations from Dependency Track.
        Returns:
            list: List of policy violations or None if request fails
        """
        url = f"{self.url}/api/v1/violation/project/{project_id}"
        req_headers = {'X-Api-Key': self.api_key, 'Content-Type': 'application/json'}
        try:
            response = requests.get(url, headers=req_headers)
            response.raise_for_status()  # Raises an HTTPError for bad responses
            return response.json()
        except requests.exceptions.RequestException as e:
            self.print_stderr(f"Error getting Dependency Track project violations: {e}")
            return e

    def get_project_by_id(self, project_id:str):
        """
        Get a Dependency Track project by id.

        Queries the Dependency Track API to get a project by id

        Returns:
            dict
        """

        if self.trace:
            self.print_trace(f'URL: {self.url}')
            self.print_trace(f'Project UUID: {project_id}')

        url = f"{self.url}/api/v1/project/{project_id}"
        req_headers = {'X-Api-Key': self.api_key, 'Content-Type': 'application/json'}
        try:
            response = requests.get(url, headers=req_headers)
            response.raise_for_status()  # Raises an HTTPError for bad responses

            return response.json()

        except requests.exceptions.RequestException as e:
            self.print_stderr(f"Error getting project status: {e}")
            return None