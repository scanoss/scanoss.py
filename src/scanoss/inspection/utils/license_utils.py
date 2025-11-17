"""
SPDX-License-Identifier: MIT

  Copyright (c) 2024, SCANOSS

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

from scanoss.osadl import Osadl

from ...scanossbase import ScanossBase


class LicenseUtil(ScanossBase):
    """
    A utility class for handling software licenses, particularly copyleft licenses.

    Uses OSADL (Open Source Automation Development Lab) authoritative copyleft data
    with optional include/exclude/explicit filters.
    """

    BASE_SPDX_ORG_URL = 'https://spdx.org/licenses'

    def __init__(self, debug: bool = False, trace: bool = True, quiet: bool = False):
        super().__init__(debug, trace, quiet)
        self.osadl = Osadl(debug=debug, trace=trace, quiet=quiet)
        self.include_licenses = set()
        self.exclude_licenses = set()
        self.explicit_licenses = set()

    def init(self, include: str = None, exclude: str = None, explicit: str = None):
        """
        Initialize copyleft license filters.

        :param include: Comma-separated licenses to mark as copyleft (in addition to OSADL)
        :param exclude: Comma-separated licenses to mark as NOT copyleft (override OSADL)
        :param explicit: Comma-separated licenses to use exclusively (ignore OSADL)
        """
        # Reset previous filters so init() can be safely called multiple times
        self.include_licenses.clear()
        self.exclude_licenses.clear()
        self.explicit_licenses.clear()

        # Parse explicit list (if provided, ignore OSADL completely)
        if explicit:
            self.explicit_licenses = {lic.strip().lower() for lic in explicit.split(',') if lic.strip()}
            self.print_debug(f'Explicit copyleft licenses: {self.explicit_licenses}')
            return

        # Parse include list (mark these as copyleft in addition to OSADL)
        if include:
            self.include_licenses = {lic.strip().lower() for lic in include.split(',') if lic.strip()}
            self.print_debug(f'Include licenses: {self.include_licenses}')

        # Parse exclude list (mark these as NOT copyleft, overriding OSADL)
        if exclude:
            self.exclude_licenses = {lic.strip().lower() for lic in exclude.split(',') if lic.strip()}
            self.print_debug(f'Exclude licenses: {self.exclude_licenses}')

    def is_copyleft(self, spdxid: str) -> bool:
        """
        Check if a license is copyleft.

        Logic:
        1. If explicit list provided → check if license in explicit list
        2. If license in include list → return True
        3. If license in exclude list → return False
        4. Otherwise → use OSADL authoritative data

        :param spdxid: SPDX license identifier
        :return: True if copyleft, False otherwise
        """
        if not spdxid:
            self.print_debug('No license ID provided for copyleft check')
            return False

        spdxid_lc = spdxid.lower()

        # Explicit mode: use only the explicit list
        if self.explicit_licenses:
            return spdxid_lc in self.explicit_licenses

        # Include filter: if license in include list, force copyleft=True
        if spdxid_lc in self.include_licenses:
            return True

        # Exclude filter: if license in exclude list, force copyleft=False
        if spdxid_lc in self.exclude_licenses:
            return False

        # No filters matched, use OSADL authoritative data
        return self.osadl.is_copyleft(spdxid)

    def get_spdx_url(self, spdxid: str) -> str:
        """
        Generate the URL for the SPDX page of a license.

        :param spdxid: The SPDX identifier of the license
        :return: The URL of the SPDX page for the given license
        """
        return f'{self.BASE_SPDX_ORG_URL}/{spdxid}.html'



#
# End of LicenseUtil Class
#
