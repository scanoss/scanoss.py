"""
SPDX-License-Identifier: MIT
"""

import unittest
from unittest.mock import MagicMock, patch

from scanoss.scanossapi import ScanossApi


class ScanossApiHttpErrorTest(unittest.TestCase):

    def test_503_retries_and_reports_server_body_without_rate_limit_wording(self):
        scanoss_api = ScanossApi(url='https://example.com', retry=1)
        response = MagicMock()
        response.status_code = 503
        response.text = 'gateway circuit breaker open'
        scanoss_api.session.post = MagicMock(side_effect=[response, response])
        scanoss_api.save_bad_req_wfp = MagicMock()

        with patch('time.sleep'):
            with self.assertRaises(Exception) as raised:
                scanoss_api.scan('file=wfp')

        message = str(raised.exception)
        self.assertIn('HTTP 503', message)
        self.assertIn('gateway circuit breaker open', message)
        self.assertNotIn('service limits', message)
        self.assertEqual(scanoss_api.session.post.call_count, 2)


if __name__ == '__main__':
    unittest.main()
