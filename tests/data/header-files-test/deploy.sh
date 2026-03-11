#!/bin/bash
# Copyright (c) 2024 HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0
#
# This script deploys the application to the target environment.
# It handles building, testing, and deploying in a single step.

set -euo pipefail

# Configuration
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
readonly BUILD_DIR="${PROJECT_ROOT}/build"
readonly DEPLOY_ENV="${1:-staging}"
readonly VERSION="${2:-$(git describe --tags --always)}"
readonly TIMESTAMP="$(date -u +%Y%m%d%H%M%S)"

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*" >&2
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
}

check_prerequisites() {
    local missing=()

    for cmd in docker kubectl jq; do
        if ! command -v "$cmd" &> /dev/null; then
            missing+=("$cmd")
        fi
    done

    if [ ${#missing[@]} -gt 0 ]; then
        log_error "Missing required tools: ${missing[*]}"
        exit 1
    fi

    log_info "All prerequisites met"
}

build_image() {
    local image_tag="myapp:${VERSION}"

    log_info "Building Docker image: ${image_tag}"

    docker build \
        --build-arg VERSION="${VERSION}" \
        --build-arg BUILD_DATE="${TIMESTAMP}" \
        --tag "${image_tag}" \
        --file "${PROJECT_ROOT}/Dockerfile" \
        "${PROJECT_ROOT}"

    log_info "Image built successfully: ${image_tag}"
    echo "${image_tag}"
}

run_tests() {
    log_info "Running test suite..."

    if ! docker run --rm "myapp:${VERSION}" test; then
        log_error "Tests failed"
        exit 1
    fi

    log_info "All tests passed"
}

deploy() {
    local env="$1"
    local image_tag="$2"

    log_info "Deploying ${image_tag} to ${env}"

    kubectl set image "deployment/myapp" \
        "myapp=${image_tag}" \
        --namespace="${env}" \
        --record

    kubectl rollout status "deployment/myapp" \
        --namespace="${env}" \
        --timeout=300s

    log_info "Deployment to ${env} completed successfully"
}

main() {
    log_info "Starting deployment pipeline"
    log_info "Environment: ${DEPLOY_ENV}"
    log_info "Version: ${VERSION}"

    check_prerequisites

    local image_tag
    image_tag=$(build_image)

    run_tests

    deploy "${DEPLOY_ENV}" "${image_tag}"

    log_info "Pipeline completed successfully"
}

main "$@"