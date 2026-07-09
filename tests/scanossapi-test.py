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
    def test_429_retry_after_then_success(self, mock_sleep):
        """The gateway now returns 429 for rate limits: retry, honour Retry-After, then succeed."""
        api = ScanossApi(retry=3, quiet=True)
        rate_limited = _mock_response(
            requests.codes.too_many_requests,
            headers={'Retry-After': '2', 'X-Ratelimit-Burst-Capacity': '50'},
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
    def test_429_honours_differing_retry_after_across_retries(self, mock_sleep):
        """Each retry must honour its own Retry-After value, not a fixed backoff."""
        api = ScanossApi(retry=5, quiet=True)
        first = _mock_response(requests.codes.too_many_requests, headers={'Retry-After': '2'})
        second = _mock_response(requests.codes.too_many_requests, headers={'Retry-After': '4'})
        ok = _mock_response(200, json_body={'result': 'ok'})
        api.session = MagicMock()
        api.session.post.side_effect = [first, second, ok]

        result = api.scan('dummy-wfp')

        self.assertEqual(result, {'result': 'ok'})
        self.assertEqual([c.args[0] for c in mock_sleep.call_args_list], [2, 4])

    @patch('scanoss.scanossapi.time.sleep', return_value=None)
    def test_429_aborts_after_retries_exhausted_with_rate_limit_message(self, mock_sleep):
        api = ScanossApi(retry=1, quiet=True)
        body = '{"error":"Rate limit exceeded","message":"Retry in 1s.","retry_after":1}'
        rate_limited = _mock_response(
            requests.codes.too_many_requests, headers={'Retry-After': '1'}, text=body,
        )
        api.session = MagicMock()
        api.session.post.return_value = rate_limited

        with self.assertRaises(Exception) as ctx:
            api.scan('dummy-wfp')
        msg = str(ctx.exception)
        self.assertIn('429', msg)
        self.assertIn('rate limit', msg.lower())
        self.assertIn(body, msg)  # the actual server response body is surfaced
        # retry_limit=1 => one initial attempt + one retry = 2 posts
        self.assertEqual(api.session.post.call_count, 2)

    @patch('scanoss.scanossapi.time.sleep', return_value=None)
    def test_503_generic_outage_not_reported_as_rate_limit(self, mock_sleep):
        """A generic 503 (circuit breaker) must surface status + body, NOT claim a rate limit."""
        api = ScanossApi(retry=1, quiet=True)
        body = 'upstream connect error or disconnect/reset before headers'
        outage = _mock_response(requests.codes.service_unavailable, text=body)
        api.session = MagicMock()
        api.session.post.return_value = outage

        with self.assertRaises(Exception) as ctx:
            api.scan('dummy-wfp')
        msg = str(ctx.exception)
        self.assertIn('503', msg)
        self.assertIn('currently unavailable', msg.lower())
        self.assertNotIn('rate limit', msg.lower())
        self.assertIn(body, msg)  # the actual server response body is surfaced
        self.assertEqual(api.session.post.call_count, 2)


if __name__ == '__main__':
    unittest.main()
