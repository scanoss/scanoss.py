"""
SPDX-License-Identifier: MIT

  Copyright (c) 2021, SCANOSS

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

import argparse
import os
import sys
import traceback
from dataclasses import asdict
from pathlib import Path
from typing import List

import pypac

from scanoss.cryptography import Cryptography, create_cryptography_config_from_args
from scanoss.delta import Delta
from scanoss.export.dependency_track import DependencyTrackExporter
from scanoss.scanners.container_scanner import (
    DEFAULT_SYFT_COMMAND,
    DEFAULT_SYFT_TIMEOUT,
    ContainerScanner,
    create_container_scanner_config_from_args,
)
from scanoss.scanners.folder_hasher import (
    FolderHasher,
    create_folder_hasher_config_from_args,
)
from scanoss.scanossgrpc import (
    ScanossGrpc,
    ScanossGrpcError,
    create_grpc_config_from_args,
)

from .components import Components
from .constants import (
    DEFAULT_API_TIMEOUT,
    DEFAULT_COPYLEFT_LICENSE_SOURCES,
    DEFAULT_HFH_DEPTH,
    DEFAULT_HFH_MIN_ACCEPTED_SCORE,
    DEFAULT_HFH_RANK_THRESHOLD,
    DEFAULT_HFH_RECURSIVE_THRESHOLD,
    DEFAULT_POST_SIZE,
    DEFAULT_RETRY,
    DEFAULT_TIMEOUT,
    MIN_TIMEOUT,
    PYTHON_MAJOR_VERSION,
    VALID_LICENSE_SOURCES,
)
from .csvoutput import CsvOutput
from .cyclonedx import CycloneDx
from .filecount import FileCount
from .gitlabqualityreport import GitLabQualityReport
from .inspection.policy_check.dependency_track.project_violation import (
    DependencyTrackProjectViolationPolicyCheck,
)
from .inspection.policy_check.scanoss.copyleft import Copyleft
from .inspection.policy_check.scanoss.undeclared_component import UndeclaredComponent
from .inspection.summary.component_summary import ComponentSummary
from .inspection.summary.license_summary import LicenseSummary
from .inspection.summary.match_summary import MatchSummary
from .results import Results
from .scancodedeps import ScancodeDeps
from .scanner import FAST_WINNOWING, Scanner
from .scanners.scanner_config import create_scanner_config_from_args
from .scanners.scanner_hfh import ScannerHFH
from .scanoss_settings import ScanossSettings, ScanossSettingsError
from .scantype import ScanType
from .spdxlite import SpdxLite
from .threadeddependencies import SCOPE
from .utils.file import validate_json_file

HEADER_PARTS_COUNT = 2


def print_stderr(*args, **kwargs):
    """
    Print the given message to STDERR
    """
    print(*args, file=sys.stderr, **kwargs)