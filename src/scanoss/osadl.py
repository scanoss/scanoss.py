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

import json
import sys

import importlib_resources

from scanoss.scanossbase import ScanossBase


class Osadl(ScanossBase):
    """
    OSADL data accessor class.

    Provides access to OSADL (Open Source Automation Development Lab) authoritative
    checklist data for license analysis.

    Data is loaded once at class level and shared across all instances for efficiency.

    Data source: https://www.osadl.org/fileadmin/checklists/copyleft.json
    License: CC-BY-4.0
    """

    _shared_copyleft_data = {}
    _data_loaded = False

    def __init__(self, debug: bool = False, trace: bool = True, quiet: bool = False):
        """
        Initialize the Osadl class.
        Data is loaded once at class level and shared across all instances.
        """
        super().__init__(debug, trace, quiet)
        self._load_copyleft_data()


    def _load_copyleft_data(self) -> bool:
        """
        Load the embedded OSADL copyleft JSON file into class-level shared data.
        Data is loaded only once and shared across all instances.

        :return: True if successful, False otherwise
        """
        if Osadl._data_loaded:
            return True

        # OSADL copyleft license checklist from: https://www.osadl.org/Checklists
        # Data source: https://www.osadl.org/fileadmin/checklists/copyleft.json
        # License: CC-BY-4.0 (Creative Commons Attribution 4.0 International)
        # Copyright: (C) 2017 - 2024 Open Source Automation Development Lab (OSADL) eG
        try:
            f_name = importlib_resources.files(__name__) / 'data/osadl-copyleft.json'
            with importlib_resources.as_file(f_name) as f:
                with open(f, 'r', encoding='utf-8') as file:
                    data = json.load(file)
        except Exception as e:
            self.print_stderr(f'ERROR: Problem loading OSADL copyleft data: {e}')
            return False

        # Process copyleft data
        copyleft = data.get('copyleft', {})
        if not copyleft:
            self.print_stderr('ERROR: No copyleft data found in OSADL JSON')
            return False

        # Store in class-level shared dictionary
        for lic_id, status in copyleft.items():
            # Normalize license ID (lowercase) for consistent lookup
            lic_id_lc = lic_id.lower()
            Osadl._shared_copyleft_data[lic_id_lc] = status

        Osadl._data_loaded = True
        self.print_debug(f'Loaded {len(Osadl._shared_copyleft_data)} OSADL copyleft entries')
        return True

    def is_copyleft(self, spdx_id: str) -> bool:
        """
        Check if a license is copyleft according to OSADL data.

        Returns True for both strong copyleft ("Yes") and weak/restricted copyleft ("Yes (restricted)").

        :param spdx_id: SPDX license identifier
        :return: True if copyleft, False otherwise
        """
        if not spdx_id:
            self.print_debug('No license ID provided for copyleft check')
            return False

        # Normalize lookup
        spdx_id_lc = spdx_id.lower()
        # Use class-level shared data
        status = Osadl._shared_copyleft_data.get(spdx_id_lc)

        if not status:
            self.print_debug(f'No OSADL copyleft data for license: {spdx_id}')
            return False

        # Consider both "Yes" and "Yes (restricted)" as copyleft (case-insensitive)
        return status.lower().startswith('yes')


#
# End of Osadl Class
#
