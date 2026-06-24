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

import unittest
from unittest.mock import MagicMock, patch

import requests

from scanoss.scanossapi import DEFAULT_RETRY_AFTER, MAX_RETRY_AFTER, ScanossApi, parse_retry_after


def _mock_response(status_code, headers=None, json_body=None, text='{}'):
    resp = MagicMock()
    resp.status_code = status_code
    resp.headers = headers if headers is not None else {}
    resp.text = text
    if json_body is not None:
        resp.json.return_value = json_body
    else:
        resp.json.return_value = {}
    return resp


class MyTestCase(unittest.TestCase):

    def test_scanoss_generic_headers(self):
        scanoss_api = ScanossApi(debug=True, req_headers={'x-api-key': '123455',
                                                          'generic-header': 'generic-header-value'})
        required_keys = ('x-api-key', 'X-Session', 'User-Agent', 'user-agent', 'generic-header')
        valid_headers = True
        for key, value in scanoss_api.headers.items():
            if key not in required_keys:
                valid_headers = False
        self.assertTrue(valid_headers)


class RetryAfterParsingTestCase(unittest.TestCase):

    def test_header_takes_precedence(self):
        resp = _mock_response(503, headers={'Retry-After': '7'}, json_body={'retry_after': 99})
        self.assertEqual(parse_retry_after(resp), 7)

    def test_falls_back_to_json_body(self):
        resp = _mock_response(503, headers={}, json_body={'retry_after': 12})
        self.assertEqual(parse_retry_after(resp), 12)

    def test_default_when_no_hint(self):
        resp = _mock_response(503, headers={}, json_body={})
        self.assertEqual(parse_retry_after(resp), DEFAULT_RETRY_AFTER)

    def test_non_numeric_header_falls_back(self):
        resp = _mock_response(503, headers={'Retry-After': 'soon'}, json_body={'retry_after': 4})
        self.assertEqual(parse_retry_after(resp), 4)

    def test_non_numeric_everything_uses_default(self):
        resp = _mock_response(503, headers={'Retry-After': 'soon'}, json_body={'retry_after': 'nope'})
        self.assertEqual(parse_retry_after(resp), DEFAULT_RETRY_AFTER)

    def test_caps_at_maximum(self):
        resp = _mock_response(503, headers={'Retry-After': '99999'})
        self.assertEqual(parse_retry_after(resp), MAX_RETRY_AFTER)

    def test_negative_uses_default(self):
        resp = _mock_response(503, headers={'Retry-After': '-3'})
        self.assertEqual(parse_retry_after(resp), DEFAULT_RETRY_AFTER)

    def test_none_response_uses_default(self):
        self.assertEqual(parse_retry_after(None), DEFAULT_RETRY_AFTER)


class RateLimitRetryTestCase(unittest.TestCase):

    @patch('scanoss.scanossapi.time.sleep', return_value=None)
    def test_503_retry_after_then_success(self, mock_sleep):
        api = ScanossApi(retry=3, quiet=True)
        rate_limited = _mock_response(
            requests.codes.service_unavailable,
            headers={'Retry-After': '2'},
            json_body={'error': 'Rate limit exceeded', 'retry_after': 2, 'strategy': 'token_bucket'},
            text='{"error":"Rate limit exceeded"}',
        )
        ok = _mock_response(200, json_body={'result': 'ok'})
        api.session = MagicMock()
        api.session.post.side_effect = [rate_limited, ok]

        result = api.scan('dummy-wfp')

        self.assertEqual(result, {'result': 'ok'})
        self.assertEqual(api.session.post.call_count, 2)  # retried instead of aborting
        mock_sleep.assert_called_once_with(2)  # honoured Retry-After header

    @patch('scanoss.scanossapi.time.sleep', return_value=None)
    def test_503_aborts_after_retries_exhausted(self, mock_sleep):
        api = ScanossApi(retry=1, quiet=True)
        rate_limited = _mock_response(
            requests.codes.service_unavailable,
            headers={'Retry-After': '1'},
            json_body={'error': 'Rate limit exceeded', 'retry_after': 1},
            text='{"error":"Rate limit exceeded"}',
        )
        api.session = MagicMock()
        api.session.post.return_value = rate_limited

        with self.assertRaises(Exception) as ctx:
            api.scan('dummy-wfp')
        self.assertIn('service limits being exceeded', str(ctx.exception))
        # retry_limit=1 => one initial attempt + one retry = 2 posts
        self.assertEqual(api.session.post.call_count, 2)