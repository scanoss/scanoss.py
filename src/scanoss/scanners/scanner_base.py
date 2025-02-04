from abc import ABC
from typing import Optional

from scanoss.scanners.scanner_config import ScannerConfig
from scanoss.scanossbase import ScanossBase


class ScannerBase(ScanossBase, ABC):
    """
    Base class for all scanners
    """

    def __init__(self, config: Optional[ScannerConfig] = None):
        if config is None:
            config = ScannerConfig()

        super().__init__(
            debug=config.debug,
            trace=config.trace,
            quiet=config.quiet,
        )
