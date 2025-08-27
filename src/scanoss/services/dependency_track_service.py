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
            raise ValueError("Error: Dependency Track URL is required")
        self.url = url.strip().rstrip('/')
        if not api_key:
            raise ValueError("Error: Dependency Track API key is required")
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
        if not name or not version:
            self.print_stderr('Error: Missing name or version.')
            return None
        # Use the project search endpoint
        params = {
            'name': name,
            'version': version
        }
        self.print_debug(f'Searching for project by: {params}')
        return self.get_dep_track_data(f'{self.url}/api/v1/project/lookup', params)

    def get_project_status(self, upload_token):
        """
        Get Dependency Track project processing status.

        Queries the Dependency Track API to check if the project upload
        processing is complete using the upload token.

        Returns:
            dict: Project status information or None if request fails
        """
        if not upload_token:
            self.print_stderr('Error: Missing upload token. Cannot search for project status.')
            return None
        self.print_trace(f'URL: {self.url} Upload token: {upload_token}')
        return self.get_dep_track_data(f'{self.url}/api/v1/event/token/{upload_token}')

    def get_project_violations(self,project_id:str):
        """
        Get project violations from Dependency Track.

        Waits for project processing to complete, then retrieves all policy
        violations for the specified project ID.

        Returns:
        List of policy violations or None if the request fails
        """
        if not project_id:
            self.print_stderr('Error: Missing project id. Cannot search for project violations.')
            return None
        # Return the result as-is - None indicates API failure, empty list means no violations
        return self.get_dep_track_data(f'{self.url}/api/v1/violation/project/{project_id}')

    def get_project_by_id(self, project_id:str):
        """
        Get a Dependency Track project by id.

        Queries the Dependency Track API to get a project by id

        Returns:
            dict
        """
        if not project_id:
            self.print_stderr('Error: Missing project id. Cannot search for project.')
            return None
        self.print_trace(f'URL: {self.url}, UUID: {project_id}')
        return self.get_dep_track_data(f'{self.url}/api/v1/project/{project_id}')

    def get_dep_track_data(self, uri, params=None):
        if not uri:
            self.print_stderr('Error: Missing URI. Cannot search for project.')
            return None
        req_headers = {'X-Api-Key': self.api_key, 'Content-Type': 'application/json'}
        try:
            if params:
                response = requests.get(uri, headers=req_headers, params=params)
            else:
                response = requests.get(uri, headers=req_headers)
            response.raise_for_status()  # Raises an HTTPError for bad responses
            return response.json()
        except requests.exceptions.RequestException as e:
            self.print_stderr(f"Error: Problem getting project data: {e}")
        return None
