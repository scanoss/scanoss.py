#!/usr/bin/env python3
"""
SCANOSS SDK Example: WFP Generation and Scanning

This example demonstrates how to:
1. Generate WFP fingerprints from a folder
2. Save fingerprints to disk
3. Reuse saved fingerprints for multiple scans

Usage:
    python wfp_scan_example.py
"""

import os

from scanoss.scanner import Scanner
from scanoss.scantype import ScanType

# Get the directory where this script is located
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Sample paths relative to this script
SAMPLE_CODE_DIR = os.path.join(SCRIPT_DIR, 'sample_code')
OUTPUT_DIR = os.path.join(SCRIPT_DIR, 'output')
WFP_FILE = os.path.join(OUTPUT_DIR, 'fingerprints.wfp')
RESULTS_FILE = os.path.join(OUTPUT_DIR, 'results.json')


def main():
    # Create output directory if it doesn't exist
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Step 1: Create Scanner instance with options
    scanner = Scanner(
        debug=True,
        quiet=False,
        scan_output=RESULTS_FILE,  # Where to save scan results
        # api_key='your-api-key',  # Optional: your SCANOSS API key
        scan_options=ScanType.SCAN_FILES.value | ScanType.SCAN_SNIPPETS.value,  # File and snippet scanning only
    )

    # Step 2: Generate and save WFP fingerprints to disk
    print(f'Generating fingerprints from: {SAMPLE_CODE_DIR}')
    print(f'Saving fingerprints to: {WFP_FILE}')
    scanner.wfp_folder(
        scan_dir=SAMPLE_CODE_DIR,
        wfp_file=WFP_FILE,
    )
    print('Fingerprints generated successfully!\n')

    # Step 3: Reuse the saved WFP for multiple scans
    print(f'Scanning using fingerprints: {WFP_FILE}')
    print(f'Results will be saved to: {RESULTS_FILE}')
    scanner.scan_wfp_with_options(
        wfp_file=WFP_FILE,
        deps_file='',  # No dependency file needed since we disabled dependency scanning
    )
    print('Scan completed!\n')

    #You can run additional scans with the same fingerprints
    # scanner.scan_wfp_with_options(
    #     wfp_file=WFP_FILE,
    #     deps_file='',     # No dependency file needed since we disabled dependency scanning
    # )


if __name__ == '__main__':
    main()
