
#vars
IMAGE_NAME=scanoss-py
REPO=scanoss
DOCKER_FULLNAME=${REPO}/${IMAGE_NAME}
GHCR_FULLNAME=ghcr.io/${REPO}/${IMAGE_NAME}
VERSION=$(shell ./version.py)

# HELP
# This will output the help for each task
# thanks to https://marmelab.com/blog/2016/02/29/auto-documented-makefile.html
.PHONY: help

help: ## This help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

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
	python3 setup.py develop --user

dev_uninstall:  ## Uninstall Python dev setup for the current user
	@echo "Uninstalling dev env..."
	python3 setup.py develop --user --uninstall
	@rm -f venv/bin/scanoss-py
	@rm -rf src/scanoss.egg-info

dist: clean dev_uninstall date_time  ## Prepare Python package into a distribution
	@echo "Build deployable package for distribution $(VERSION)..."
	python3 setup.py sdist bdist_wheel
	twine check dist/*

publish_test:  ## Publish the Python package to TestPyPI
	@echo "Publishing package to TestPyPI..."
	twine upload --repository testpypi dist/*

publish:  ## Publish Python package to PyPI
	@echo "Publishing package to PyPI..."
	twine upload dist/*

package_all: dist publish ## Build & Publish Python package to PyPI

ghcr_build: dist ## Build GitHub container image
	@echo "Building GHCR container image..."
	docker build --no-cache -t $(GHCR_FULLNAME) --platform linux/amd64 .

ghcr_tag:  ## Tag the latest GH container image with the version from Python
	@echo "Tagging GHCR latest image with $(VERSION)..."
	docker tag $(GHCR_FULLNAME):latest $(GHCR_FULLNAME):$(VERSION)

ghcr_push:  ## Push the GH container image to GH Packages
	@echo "Publishing GHCR container $(VERSION)..."
	docker push $(GHCR_FULLNAME):$(VERSION)
	docker push $(GHCR_FULLNAME):latest

ghcr_all: ghcr_build ghcr_tag ghcr_push  ## Execute all GitHub Package container actions

docker_build:  ## Build Docker container image
	@echo "Building Docker image..."
	docker build --no-cache -t $(DOCKER_FULLNAME) .

docker_tag:  ## Tag the latest Docker container image with the version from Python
	@echo "Tagging Docker latest image with $(VERSION)..."
	docker tag $(DOCKER_FULLNAME):latest $(DOCKER_FULLNAME):$(VERSION)

docker_push:  ## Push the Docker container image to DockerHub
	@echo "Publishing Docker container $(VERSION)..."
	docker push $(DOCKER_FULLNAME):$(VERSION)
	docker push $(DOCKER_FULLNAME):latest

docker_all: docker_build docker_tag docker_push  ## Execute all DockerHub container actions
