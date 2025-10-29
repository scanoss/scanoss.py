#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Lint Python files changed since merge base with origin/main
# Usage: linter.sh [--fix] [--docker]

set -e

# Parse arguments
FIX_FLAG=""
USE_DOCKER=false

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
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--fix] [--docker]"
            exit 1
            ;;
    esac
done

# Find merge base with origin/main
merge_base=$(git merge-base origin/main HEAD)

# Get all changed Python files since merge base
files=$(git diff --name-only "$merge_base" HEAD | grep '\.py$' || true)

# Check if there are any Python files changed
if [ -z "$files" ]; then
    echo "No Python files changed"
    exit 0
fi

# Run linter
if [ "$USE_DOCKER" = true ]; then
  # Run with Docker
  docker run --rm -v "$(pwd)":/src -w /src ghcr.io/astral-sh/ruff:0.14.2 check ${files} ${FIX_FLAG}
else
  # Run locally
  python3 -m ruff check ${files} ${FIX_FLAG}
fi