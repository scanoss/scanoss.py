
#vars
IMAGE_BASE=scanoss-py-base
IMAGE_NAME=scanoss-py
REPO=scanoss
DOCKER_FULLNAME_BASE=${REPO}/${IMAGE_BASE}
DOCKER_FULLNAME=${REPO}/${IMAGE_NAME}
GHCR_FULLNAME_BASE=ghcr.io/${REPO}/${IMAGE_BASE}
GHCR_FULLNAME=ghcr.io/${REPO}/${IMAGE_NAME}
VERSION=$(shell ./version.py)

# HELP
# This will output the help for each task
# thanks to https://marmelab.com/blog/2016/02/29/auto-documented-makefile.html
.PHONY: help

help: ## This help
	@awk 'BEGIN {FS = ":.*?## "} /^[0-9a-zA-Z_-]+:.*?## / {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.DEFAULT_GOAL := help

clean: date_time_clean ## Clean all dev data
	@echo "Removing dev and distribution data..."
	@rm -rf dist/* build/* venv/bin/scanoss-py src/scanoss.egg-info

date_time_clean:  ## Setup blank datetime data field
	@rm -rf src/scanoss/data/build_date.txt
	@echo "" > src/scanoss/data/build_date.txt

date_time:  ## Setup package build date
	@rm -rf src/scanoss/data/build_date.txt
	python3 date_time.py

dev_setup: date_time_clean  ## Setup Python dev env for the current user
	@echo "Setting up dev env for the current user..."
	pip3 install -e .

dev_uninstall:  ## Uninstall Python dev setup for the current user
	@echo "Uninstalling dev env..."
	pip3 uninstall -y scanoss
	@rm -f venv/bin/scanoss-py
	@rm -rf src/scanoss.egg-info

dist: clean dev_uninstall date_time  ## Prepare Python package into a distribution
	@echo "Build deployable package for distribution $(VERSION)..."
	python3 -m build
	twine check dist/*

publish_test:  ## Publish the Python package to TestPyPI
	@echo "Publishing package to TestPyPI..."
	twine upload --repository testpypi dist/*

publish:  ## Publish Python package to PyPI
	@echo "Publishing package to PyPI..."
	twine upload dist/*

package_all: dist publish  ## Build & Publish Python package to PyPI

ghcr_build: dist  ## Build GitHub container image with local arch
	@echo "Building GHCR container image..."
	docker build --target with_entry_point -t $(GHCR_FULLNAME) .

ghcr_build_base: dist  ## Build GitHub container base image with local arch (no entrypoint)
	@echo "Building GHCR base container image..."
	docker build --target no_entry_point -t $(GHCR_FULLNAME_BASE) .

ghcr_build_jenkins: dist  ## Build GitHub container jenkins image with local arch
	@echo "Building GHCR base container image..."
	docker build --target jenkins -t $(GHCR_FULLNAME_BASE) .

ghcr_amd64: dist  ## Build GitHub AMD64 container image
	@echo "Building GHCR AMD64 container image..."
	docker build --target with_entry_point -t $(GHCR_FULLNAME)  --platform linux/amd64 .

ghcr_arm64: dist  ## Build GitHub ARM64 container image
	@echo "Building GHCR ARM64 container image..."
	docker build --target with_entry_point -t $(GHCR_FULLNAME)  --platform linux/arm64 .

ghcr_tag:  ## Tag the latest GH container image with the version from Python
	@echo "Tagging GHCR latest image with $(VERSION)..."
	docker tag $(GHCR_FULLNAME):latest $(GHCR_FULLNAME):$(VERSION)

ghcr_push:  ## Push the GH container image to GH Packages
	@echo "Publishing GHCR container $(VERSION)..."
	docker push $(GHCR_FULLNAME):$(VERSION)
	docker push $(GHCR_FULLNAME):latest

ghcr_release: dist  ## Build/Publish GitHub multi-platform container image
	@echo "Building & Releasing GHCR multi-platform container image $(VERSION)..."
	docker buildx build --push --target with_entry_point -t $(GHCR_FULLNAME):$(VERSION) --platform linux/arm64,linux/amd64 .

ghcr_all: ghcr_release  ## Execute all GHCR container actions

docker_build: dist  ## Build Docker container image with local arch
	@echo "Building Docker image..."
	docker build --no-cache --target with_entry_point -t $(DOCKER_FULLNAME) .

docker_build_base: dist  ## Build Base Docker container image with local arch - no entrypoint
	@echo "Building Docker image..."
	docker build --no-cache --target no_entry_point -t $(DOCKER_FULLNAME_BASE) .

docker_build_jenkins: dist  ## Build Jenkins Docker container image with local arch
	@echo "Building Docker image..."
	docker build --no-cache --target jenkins -t $(DOCKER_FULLNAME_BASE) .

docker_amd64: dist  ## Build Docker AMD64 container image
	@echo "Building Docker AMD64 container image..."
	docker build --target with_entry_point -t $(DOCKER_FULLNAME)  --platform linux/amd64 .

docker_arm64: dist  ## Build Docker ARM64 container image
	@echo "Building Docker ARM64 container image..."
	docker build --target with_entry_point -t $(DOCKER_FULLNAME)  --platform linux/arm64 .

docker_tag:  ## Tag the latest Docker container image with the version from Python
	@echo "Tagging Docker latest image with $(VERSION)..."
	docker tag $(DOCKER_FULLNAME):latest $(DOCKER_FULLNAME):$(VERSION)

docker_push:  ## Push the Docker container image to DockerHub
	@echo "Publishing Docker container $(VERSION)..."
	docker push $(DOCKER_FULLNAME):$(VERSION)
	docker push $(DOCKER_FULLNAME):latest

docker_release: dist  ## Build/Publish Docker multi-platform container image
	@echo "Building & Releasing Docker multi-platform container image $(VERSION)..."
	docker buildx build --push --target with_entry_point -t $(DOCKER_FULLNAME):$(VERSION) --platform linux/arm64,linux/amd64 .

docker_all: docker_release  ## Execute all DockerHub container actions
