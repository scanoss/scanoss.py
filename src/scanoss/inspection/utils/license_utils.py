from scanoss.scanossbase import ScanossBase

DEFAULT_COPYLEFT_LICENSES = {
            'gpl-1.0-only', 'gpl-2.0-only', 'gpl-3.0-only', 'agpl-3.0-only',
            'sleepycat', 'watcom-1.0', 'gfdl-1.1-only', 'gfdl-1.2-only',
            'gfdl-1.3-only', 'lgpl-2.1-only', 'lgpl-3.0-only', 'mpl-1.1',
            'mpl-2.0', 'epl-1.0', 'epl-2.0', 'cddl-1.0', 'cddl-1.1',
            'cecill-2.1', 'artistic-1.0', 'artistic-2.0', 'cc-by-sa-4.0'
}

class LicenseUtil(ScanossBase):
    """
        A utility class for handling software licenses, particularly copyleft licenses.

        This class provides functionality to initialize, manage, and query a set of
        copyleft licenses. It also offers a method to generate URLs for license information.
    """
    BASE_OSADL_URL = 'https://spdx.org/licenses'
    HTML = 'html'

    def __init__(self):
        self.default_copyleft_licenses = set(DEFAULT_COPYLEFT_LICENSES)
        self.copyleft_licenses = set()


    def init(self, include: str=None, exclude: str=None, explicit: str= None):
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

        if explicit and explicit.strip():
            exp = [item.lower() for item in explicit.split(',')]
            self.copyleft_licenses = set(exp)
            return

        # If no explicit licenses were set, set default ones
        self.copyleft_licenses = self.default_copyleft_licenses.copy()

        if include and include.strip():
            inc =[item.lower() for item in include.split(',')]
            self.copyleft_licenses.update(inc)

        if exclude and exclude.strip():
            inc = [item.lower() for item in exclude.split(',')]
            for lic in inc:
                self.copyleft_licenses.discard(lic)


    def is_copyleft(self, spdxid: str) -> bool:
        """
           Check if a given license is considered copyleft.

           :param spdxid: The SPDX identifier of the license to check
           :return: True if the license is copyleft, False otherwise
        """
        return spdxid.lower() in self.copyleft_licenses

    def get_osadl(self, spdxid: str) -> str:
        """
           Generate the URL for the OSADL (Open Source Automation Development Lab) page of a license.

           :param spdxid: The SPDX identifier of the license
           :return: The URL of the OSADL page for the given license
        """
        return f"{self.BASE_OSADL_URL}/{spdxid}.{self.HTML}"


license_util = LicenseUtil()