#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Lint Python files changed since merge base with origin/main
# Usage: linter.sh [--fix] [--docker] [--all]
set -e
RUFF_IMAGE="ghcr.io/astral-sh/ruff:0.14.2"
# Parse arguments
FIX_FLAG=""
USE_DOCKER=false
ALL_FILES=false
while [[ $# -gt 0 ]]; do
    case $1 in
        --fix)
            FIX_FLAG="--fix"
            shift
            ;;
        --docker)
            USE_DOCKER=true
            shift
            ;;
        --all)
            ALL_FILES=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--fix] [--docker] [--all]"
            exit 1
            ;;
    esac
done
# Get a list of files to analyse
files=""
if [ "$ALL_FILES" = "true" ] ; then
  echo "Analysing all python files..."
  files=$(find . -type f -name "*.py" -print)
else
  # Find merge base with origin/main
  if ! git rev-parse --verify origin/main >/dev/null 2>&1; then
    echo "Error: origin/main branch not found. Ensure you have fetched from origin."
    exit 1
  fi
  merge_base=$(git merge-base origin/main HEAD)
  # Get all changed Python files since merge base
  files=$(git diff --name-only "$merge_base" HEAD | grep '\.py$' || true)
fi
# Filter out files that match exclude patterns from pyproject.toml
# this is a temporary workaround until we fix all the lint errors
filtered_files=$(echo "$files" | grep -v -E 'tests/|test_.*\.py|src/protoc_gen_swagger/|src/scanoss/api/' || true)

# Check if there are any Python files changed
if [ -z "$filtered_files" ]; then
    echo "No Python files changed"
    exit 0
fi
file_count=$(echo "${filtered_files}" | wc -l | tr -d ' ')
echo "Analysing ${file_count} files..."
# Run linter
if [ "$USE_DOCKER" = true ]; then
  # Run with Docker
  echo "$filtered_files" | xargs -r docker run --rm -v "$(pwd)":/src -w /src ${RUFF_IMAGE} check ${FIX_FLAG}
else
  # Run locally
  echo "$filtered_files" | xargs -r python3 -m ruff check ${FIX_FLAG}
fi