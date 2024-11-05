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
from ...scanossbase import ScanossBase

DEFAULT_COPYLEFT_LICENSES = {
    'agpl-3.0-only', 'artistic-1.0', 'artistic-2.0', 'cc-by-sa-4.0', 'cddl-1.0', 'cddl-1.1', 'cecill-2.1',
    'epl-1.0', 'epl-2.0', 'gfdl-1.1-only', 'gfdl-1.2-only', 'gfdl-1.3-only', 'gpl-1.0-only', 'gpl-2.0-only',
    'gpl-3.0-only', 'lgpl-2.1-only', 'lgpl-3.0-only', 'mpl-1.1', 'mpl-2.0', 'sleepycat', 'watcom-1.0'
}

class LicenseUtil(ScanossBase):
    """
        A utility class for handling software licenses, particularly copyleft licenses.

        This class provides functionality to initialize, manage, and query a set of
        copyleft licenses. It also offers a method to generate URLs for license information.
    """
    BASE_SPDX_ORG_URL = 'https://spdx.org/licenses'
    BASE_OSADL_URL = 'https://www.osadl.org/fileadmin/checklists/unreflicenses'

    def __init__(self,debug: bool = False, trace: bool = True, quiet: bool = False):
        super().__init__(debug, trace, quiet)
        self.default_copyleft_licenses = set(DEFAULT_COPYLEFT_LICENSES)
        self.copyleft_licenses = set()

    def init(self, include: str = None, exclude: str = None, explicit: str = None):
        """
            Initialize the set of copyleft licenses based on user input.

            This method allows for customization of the copyleft license set by:
            - Setting an explicit list of licenses
            - Including additional licenses to the default set
            - Excluding specific licenses from the default set

            :param include: Comma-separated string of licenses to include
            :param exclude: Comma-separated string of licenses to exclude
            :param explicit: Comma-separated string of licenses to use exclusively
        """
        if self.debug:
            self.print_stderr(f'Include Copyleft licenses: ${include}')
            self.print_stderr(f'Exclude Copyleft licenses: ${exclude}')
            self.print_stderr(f'Explicit Copyleft licenses: ${explicit}')
        if explicit:
            explicit = explicit.strip()
        if explicit:
            exp = [item.strip().lower() for item in explicit.split(',')]
            self.copyleft_licenses = set(exp)
            self.print_debug(f'Copyleft licenses: ${self.copyleft_licenses}')
            return
        # If no explicit licenses were set, set default ones
        self.copyleft_licenses = self.default_copyleft_licenses.copy()
        if include:
            include = include.strip()
        if include:
            inc =[item.strip().lower() for item in include.split(',')]
            self.copyleft_licenses.update(inc)
        if exclude:
            exclude = exclude.strip()
        if exclude:
            inc = [item.strip().lower() for item in exclude.split(',')]
            for lic in inc:
                self.copyleft_licenses.discard(lic)
        self.print_debug(f'Copyleft licenses: ${self.copyleft_licenses}')

    def is_copyleft(self, spdxid: str) -> bool:
        """
           Check if a given license is considered copyleft.

           :param spdxid: The SPDX identifier of the license to check
           :return: True if the license is copyleft, False otherwise
        """
        return spdxid.lower() in self.copyleft_licenses

    def get_spdx_url(self, spdxid: str) -> str:
        """
           Generate the URL for the SPDX page of a license.

           :param spdxid: The SPDX identifier of the license
           :return: The URL of the SPDX page for the given license
        """
        return f'{self.BASE_SPDX_ORG_URL}/{spdxid}.html'


    def get_osadl_url(self, spdxid: str) -> str:
        """
        Generate the URL for the OSADL (Open Source Automation Development Lab) page of a license.

        :param spdxid: The SPDX identifier of the license
        :return: The URL of the OSADL page for the given license
        """
        return f'{self.BASE_OSADL_URL}/{spdxid}.txt'
#
# End of LicenseUtil Class
#
