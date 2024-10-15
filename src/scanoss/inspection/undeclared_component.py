from scanoss.inspection.policy_check import PolicyCheck


class UndeclaredComponent(PolicyCheck):

    def __init__(self, debug: bool = False, trace: bool = True, quiet: bool = False, filepath: str = None,
                 format: str = None, status: str = None, output: str = None):
        super().__init__(debug, trace, quiet, filepath, format, status, output)
        self.filepath = filepath
        self.format = format
        self.output = output
        self.status = status

    def run(self):
        components = self._get_components()
