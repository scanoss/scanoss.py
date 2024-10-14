from scanoss.inspections.policyCheck import PolicyCheck
from scanoss.inspections.utils.result_utils import get_components


class Copyleft(PolicyCheck):

    def __init__(self, debug: bool = False, trace: bool = False, quiet: bool = False, filepath: str = None,
                 format: str = None, status: str = None):
        super().__init__(debug, trace, quiet,filepath,format,status)


    def run(self):
        print("File path",self.file_path)
        results = self.result.load_file(self.file_path)
        ##print("Results",results)
        components = get_components(results)
        print(components)

        """
            Inspect for copyleft licenses
        """


        """
            self.format...
            Call function depending on the format output
        """

