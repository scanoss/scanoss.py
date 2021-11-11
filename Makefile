
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

help: ## This help.
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.DEFAULT_GOAL := help

clean:  ## Clean all dev data
	@rm -rf dist/* build/* venv/bin/scanoss-py src/scanoss.egg-info

dev_setup:  ## Setup Python dev env for the current user
	python3 setup.py develop --user

dev_uninstall:  ## Uninstall Python dev setup for the current user
	python3 setup.py develop --user --uninstall
	@rm -f venv/bin/scanoss-py
	@rm -rf src/scanoss.egg-info

dist: clean dev_uninstall  ## Prepare Python package into a distribution
	python3 setup.py sdist bdist_wheel
	twine check dist/*

publish_test:  ## Publish the Python package to TestPyPI
	twine upload --repository testpypi dist/*

publish:  ## Publish Python package to PyPI
	twine upload dist/*

ghcr_build:  ## Build GitHub container image
	docker build -t $(GHCR_FULLNAME) .

ghcr_tag:  ## Tag the latest GH container image with the version from Python
	docker tag $(GHCR_FULLNAME):latest $(GHCR_FULLNAME):$(VERSION)

ghcr_push:  ## Push the GH container image to GH Packages
	docker push $(GHCR_FULLNAME):$(VERSION)
	docker push $(GHCR_FULLNAME):latest

ghcr_all: ghcr_build ghcr_tag ghcr_push  ## Execute all GitHub Package container actions

docker_build:  ## Build Docker container image
	docker build -t $(DOCKER_FULLNAME) .

docker_tag:  ## Tag the latest Docker container image with the version from Python
	docker tag $(DOCKER_FULLNAME):latest $(DOCKER_FULLNAME):$(VERSION)

docker_push:  ## Push the Docker container image to DockerHub
	docker push $(DOCKER_FULLNAME):$(VERSION)
	docker push $(DOCKER_FULLNAME):latest

docker_all: docker_build docker_tag docker_push  ## Execute all DockerHub container actions
