import os
import logging

class LicenseUtil:
    BASE_OSADL_URL = 'https://spdx.org/licenses'
    HTML = 'html'

    def __init__(self):
        self.default_copyleft_licenses = set([
            'gpl-1.0-only', 'gpl-2.0-only', 'gpl-3.0-only', 'agpl-3.0-only',
            'sleepycat', 'watcom-1.0', 'gfdl-1.1-only', 'gfdl-1.2-only',
            'gfdl-1.3-only', 'lgpl-2.1-only', 'lgpl-3.0-only', 'mpl-1.1',
            'mpl-2.0', 'epl-1.0', 'epl-2.0', 'cddl-1.0', 'cddl-1.1',
            'cecill-2.1', 'artistic-1.0', 'artistic-2.0', 'cc-by-sa-4.0'
        ])
        self.copyleft_licenses = set()
        self.copyleft_licenses = self.default_copyleft_licenses.copy()


    def is_copyleft(self, spdxid: str) -> bool:
        return spdxid.lower() in self.copyleft_licenses

    def get_osadl(self, spdxid: str) -> str:
        return f"{self.BASE_OSADL_URL}/{spdxid}.{self.HTML}"


license_util = LicenseUtil()