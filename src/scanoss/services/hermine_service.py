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

import requests

from ..scanossbase import ScanossBase

HTTP_OK = 200


class HermineService(ScanossBase):

    def __init__(  # noqa: PLR0913
            self,
            api_key: str,
            url: str,
            debug: bool = False,
            trace: bool = False,
            quiet: bool = False,
            timeout: float = 300.0,
    ):
        super().__init__(debug=debug, trace=trace, quiet=quiet)
        if not url:
            raise ValueError("Error: Hermine URL is required")
        self.url = url.strip().rstrip('/')
        if not api_key:
            raise ValueError("Error: Hermine API key is required")
        self.api_key = api_key
        self.timeout = timeout

    def get_products(self):
        """
        Look up all Hermine products.

        Returns:
            Product dictionary or None if not found
        """
        return self.get_hermine_data(f'{self.url}/api/products/')

    def get_ids(self, product_name, release_name):
        products = self.get_products()
        if products is None:
            return False
        results = products.get('results') or []
        product = next((item for item in results if item.get('name') == product_name), None)
        if product:
            product_id = product.get('id')
            releases = product.get('releases') or []
            release = next((r for r in releases if r.get('release_number') == release_name), None)
            if release:
                release_id = release.get('id')
            else:
                self.print_debug(f'Release {release_name} not found for product {product_name}. Creating new release.')
                release = self.create_release(product_id, release_name)
                if release is None:
                    return False
                release_id = release.get('id')
        else:
            self.print_debug(f'Product {product_name} not found. Creating new product.')
            product = self.create_product(product_name)
            if product is None:
                return False
            product_id = product.get('id')
            self.print_debug(f'Creating release {release_name} for product {product_name}.')
            release = self.create_release(product_id, release_name)
            if release is None:
                return False
            release_id = release.get('id')
        if product_id is None or release_id is None:
            return False
        return product_id, release_id

    def create_product(self, name):
        if not name:
            self.print_stderr('Error: Missing name.')
            return None
        data = {'name': name}
        return self.get_hermine_data(f'{self.url}/api/products/', data=data)

    def create_release(self, product_id: str, release_name: str):
        if not product_id or not release_name:
            self.print_stderr('Error: Missing product id or release name.')
            return None
        data = {
            'product': product_id,
            'release_number': release_name
        }
        return self.get_hermine_data(f'{self.url}/api/releases/', data=data)

    def get_version_purl_map(self) -> dict:
        """
        Fetch all components and return a mapping of version_id to purl.

        Returns:
            Dict mapping version ID (int) to purl (str)
        """
        purl_map = {}
        url = f'{self.url}/api/components/'
        while url:
            response = self.get_hermine_data(url)
            if response is None:
                break
            for component in response.get('results', []):
                for version in component.get('versions', []):
                    version_id = version.get('id')
                    purl = version.get('purl')
                    if version_id and purl:
                        purl_map[version_id] = purl
            url = response.get('next')
        return purl_map


    def get_hermine_data(self, uri, params=None, data=None, files=None):
        """
        Fetches data from a given URI using the Hermine API.

        Parameters:
            uri (str): The target URI for the API request. Required.
            params (dict, optional): A dictionary of query parameters for a GET
                request. Defaults to None.
            data (dict, optional): A dictionary of payload data for a POST
                request. Defaults to None.
            files (dict, optional): A dictionary of files to be uploaded

        Returns:
            dict or None: The JSON response as a Python dictionary if the request
            is successful, or None if an error occurs.
        """
        if not uri:
            self.print_stderr('Error: Missing URI. Cannot search for product.')
            return None
        req_headers = {'Authorization': f'Token {self.api_key}'}
        try:
            self.print_debug(f'URL: {uri}, Params: {params}, Data: {data}')
            if data:
                response = requests.post(uri, headers=req_headers, data=data, files=files, timeout=self.timeout)
            elif params:
                response = requests.get(uri, headers=req_headers, params=params, timeout=self.timeout)
            else:
                response = requests.get(uri, headers=req_headers, timeout=self.timeout)
            response.raise_for_status()  # Raises an HTTPError for bad responses
            return response.json()
        except requests.exceptions.RequestException as e:
            self.print_stderr(f"Error: Problem getting product data: {e}")
        return None
    