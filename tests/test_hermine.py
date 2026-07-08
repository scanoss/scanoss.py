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

import json
import os
import tempfile
import unittest
from unittest.mock import Mock, patch

import requests

from src.scanoss.export.hermine import HermineExporter
from src.scanoss.inspection.policy_check.hermine.violations import HermineViolationsPolicyCheck
from src.scanoss.inspection.policy_check.policy_check import PolicyStatus
from src.scanoss.services.hermine_service import HermineService


class HermineServiceTestCase(unittest.TestCase):
    """
    Tests for HermineService
    """

    def test_get_ids_existing_product_and_release(self):
        service = HermineService(api_key='key', url='http://hermine.test')
        products = {
            'results': [
                {'id': 1, 'name': 'prod', 'releases': [{'id': 2, 'release_number': 'rel'}]}
            ]
        }
        with patch.object(service, 'get_hermine_data', return_value=products) as mock_get:
            result = service.get_ids('prod', 'rel')
        self.assertEqual(result, (1, 2))
        mock_get.assert_called_once()

    def test_get_ids_creates_missing_release(self):
        service = HermineService(api_key='key', url='http://hermine.test')
        products = {
            'results': [
                {'id': 1, 'name': 'prod', 'releases': []}
            ]
        }
        with patch.object(service, 'get_hermine_data', return_value=products), \
                patch.object(service, 'create_release', return_value={'id': 99}) as mock_create_release:
            result = service.get_ids('prod', 'new-rel')
        self.assertEqual(result, (1, 99))
        mock_create_release.assert_called_once_with(1, 'new-rel')

    def test_get_ids_creates_missing_product_and_release(self):
        service = HermineService(api_key='key', url='http://hermine.test')
        products = {'results': []}
        with patch.object(service, 'get_hermine_data', return_value=products), \
                patch.object(service, 'create_product', return_value={'id': 5}), \
                patch.object(service, 'create_release', return_value={'id': 6}):
            result = service.get_ids('new-prod', 'new-rel')
        self.assertEqual(result, (5, 6))

    def test_get_ids_returns_false_when_products_lookup_fails(self):
        service = HermineService(api_key='key', url='http://hermine.test')
        with patch.object(service, 'get_hermine_data', return_value=None):
            result = service.get_ids('prod', 'rel')
        self.assertFalse(result)

    def test_get_ids_returns_false_when_release_creation_fails(self):
        service = HermineService(api_key='key', url='http://hermine.test')
        products = {'results': [{'id': 1, 'name': 'prod', 'releases': []}]}
        with patch.object(service, 'get_hermine_data', return_value=products), \
                patch.object(service, 'create_release', return_value=None):
            result = service.get_ids('prod', 'new-rel')
        self.assertFalse(result)

    def test_get_hermine_data_get_success(self):
        service = HermineService(api_key='key', url='http://hermine.test')
        fake_response = Mock()
        fake_response.json.return_value = {'ok': True}
        with patch('requests.get', return_value=fake_response) as mock_get:
            result = service.get_hermine_data('http://hermine.test/api/products/')
        self.assertEqual(result, {'ok': True})
        mock_get.assert_called_once()
        fake_response.raise_for_status.assert_called_once()

    def test_get_hermine_data_post_success(self):
        service = HermineService(api_key='key', url='http://hermine.test')
        fake_response = Mock()
        fake_response.json.return_value = {'id': 1}
        with patch('requests.post', return_value=fake_response) as mock_post:
            result = service.get_hermine_data('http://hermine.test/api/products/', data={'name': 'prod'})
        self.assertEqual(result, {'id': 1})
        mock_post.assert_called_once()

    def test_get_hermine_data_returns_none_on_request_error(self):
        service = HermineService(api_key='key', url='http://hermine.test')
        with patch('requests.get', side_effect=requests.exceptions.ConnectionError('boom')):
            result = service.get_hermine_data('http://hermine.test/api/products/')
        self.assertIsNone(result)

    def test_get_hermine_data_missing_uri_returns_none(self):
        service = HermineService(api_key='key', url='http://hermine.test')
        self.assertIsNone(service.get_hermine_data(None))

    def test_requires_url_and_api_key(self):
        with self.assertRaises(ValueError):
            HermineService(api_key='key', url='')
        with self.assertRaises(ValueError):
            HermineService(api_key='', url='http://hermine.test')


class HermineExporterTestCase(unittest.TestCase):
    """
    Tests for HermineExporter (export SPDX SBOM to Hermine)
    """

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.sbom_path = os.path.join(self.tmp_dir.name, 'sbom.json')
        with open(self.sbom_path, 'w') as f:
            json.dump({'spdxVersion': 'SPDX-2.3', 'name': 'test'}, f)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_upload_sbom_contents_success_writes_response_to_output_file(self):
        exporter = HermineExporter(url='http://hermine.test', api_key='key', quiet=True)
        output_file = os.path.join(self.tmp_dir.name, 'out.json')
        response_body = {'upload_token': 'abc123'}
        with patch.object(exporter.hm_service, 'get_hermine_data', return_value=response_body):
            result = exporter.upload_sbom_contents({'release': 2, 'replace': 'true'}, {}, output_file)
        self.assertTrue(result)
        with open(output_file) as f:
            self.assertEqual(json.load(f), response_body)

    def test_upload_sbom_contents_success_prints_upload_complete(self):
        exporter = HermineExporter(url='http://hermine.test', api_key='key')
        with patch.object(exporter.hm_service, 'get_hermine_data', return_value={'id': 1}), \
                patch.object(exporter, 'print_msg') as mock_print_msg:
            result = exporter.upload_sbom_contents({'release': 2, 'replace': 'true'}, {}, None)
        self.assertTrue(result)
        mock_print_msg.assert_called_once_with('Upload complete.')

    def test_upload_sbom_contents_failure_when_response_is_none(self):
        exporter = HermineExporter(url='http://hermine.test', api_key='key')
        with patch.object(exporter.hm_service, 'get_hermine_data', return_value=None), \
                patch.object(exporter, 'print_msg') as mock_print_msg:
            result = exporter.upload_sbom_contents({'release': 2, 'replace': 'true'}, {}, None)
        self.assertFalse(result)
        mock_print_msg.assert_called_once_with('Upload failed.')

    def test_upload_sbom_contents_failure_on_unexpected_error(self):
        exporter = HermineExporter(url='http://hermine.test', api_key='key')
        with patch.object(exporter.hm_service, 'get_hermine_data', side_effect=RuntimeError('boom')), \
                patch.object(exporter, 'print_msg') as mock_print_msg:
            result = exporter.upload_sbom_contents({'release': 2, 'replace': 'true'}, {}, None)
        self.assertFalse(result)
        mock_print_msg.assert_called_once_with('Upload failed.')

    def test_upload_sbom_file_returns_false_when_get_ids_fails(self):
        exporter = HermineExporter(url='http://hermine.test', api_key='key')
        with patch.object(exporter.hm_service, 'get_ids', return_value=False):
            result = exporter.upload_sbom_file(self.sbom_path, 'prod', 'rel', None)
        self.assertFalse(result)

    def test_upload_sbom_file_success_end_to_end(self):
        exporter = HermineExporter(url='http://hermine.test', api_key='key', quiet=True)
        with patch.object(exporter.hm_service, 'get_ids', return_value=(1, 2)), \
                patch.object(exporter.hm_service, 'get_hermine_data', return_value={'upload_token': 'abc'}):
            result = exporter.upload_sbom_file(self.sbom_path, 'prod', 'rel', None)
        self.assertTrue(result)

    def test_upload_sbom_file_invalid_json_returns_false(self):
        exporter = HermineExporter(url='http://hermine.test', api_key='key', quiet=True)
        bad_path = os.path.join(self.tmp_dir.name, 'bad.json')
        with open(bad_path, 'w') as f:
            f.write('not json')
        result = exporter.upload_sbom_file(bad_path, 'prod', 'rel', None)
        self.assertFalse(result)

    def test_upload_sbom_file_not_spdx_returns_false(self):
        exporter = HermineExporter(url='http://hermine.test', api_key='key', quiet=True)
        non_spdx_path = os.path.join(self.tmp_dir.name, 'non_spdx.json')
        with open(non_spdx_path, 'w') as f:
            json.dump({'name': 'test'}, f)
        result = exporter.upload_sbom_file(non_spdx_path, 'prod', 'rel', None)
        self.assertFalse(result)


class HermineViolationsPolicyCheckTestCase(unittest.TestCase):
    """
    Tests for HermineViolationsPolicyCheck
    """

    def _make_check(self, **overrides):
        kwargs = dict(
            format_type='json',
            product_id=1,
            release_id=2,
            api_key='key',
            url='http://hermine.test',
        )
        kwargs.update(overrides)
        return HermineViolationsPolicyCheck(**kwargs)

    def test_run_success_when_all_validations_pass(self):
        check = self._make_check()
        with patch.object(check.hm_service, 'get_hermine_data', return_value={'valid': True}), \
                patch.object(check.hm_service, 'get_version_purl_map', return_value={}):
            status = check.run()
        self.assertEqual(status, PolicyStatus.POLICY_SUCCESS.value)

    def test_run_fails_when_get_ids_fails(self):
        check = self._make_check(product_id=None, release_id=None, product_name='prod', release_name='rel')
        with patch.object(check.hm_service, 'get_ids', return_value=False):
            status = check.run()
        self.assertEqual(status, PolicyStatus.ERROR.value)

    def test_release_validation_reports_invalid_expressions(self):
        check = self._make_check()
        response = {
            'valid': False,
            'details': '/link',
            'invalid_expressions': [
                {'version': {'purl': 'pkg:pypi/foo@1.0', 'declared_license_expr': 'GPL-BAD'}}
            ],
        }
        with patch.object(check.hm_service, 'get_hermine_data', return_value=response):
            valid, components, link = check.release_validation()
        self.assertFalse(valid)
        self.assertEqual(link, '/link')
        self.assertEqual(components, [{'purl': 'pkg:pypi/foo@1.0', 'declared_license_expr': 'GPL-BAD'}])

    def test_json_formatter_empty_violations(self):
        check = self._make_check()
        result = check._json([])
        self.assertEqual(json.loads(result.details), [])
        self.assertEqual(result.summary, '0 policy violations were found.\n')


if __name__ == '__main__':
    unittest.main()
