
#vars
IMAGE_NAME=scanoss-py
REPO=scanoss
DOCKER_FULLNAME=${REPO}/${IMAGE_NAME}
GHCR_FULLNAME=ghcr.io/${REPO}/${IMAGE_NAME}
VERSION=$(shell ./version.py)

clean:
	@rm -rf dist/* build/* venv/bin/scanoss-py src/scanoss.egg-info

dist: clean dev_uninstall
	python3 setup.py sdist bdist_wheel
	twine check dist/*

dev_setup:
	python3 setup.py develop --user

dev_uninstall:
	python3 setup.py develop --user --uninstall
	@rm -f venv/bin/scanoss-py
	@rm -rf src/scanoss.egg-info

publish_test:
	twine upload --repository testpypi dist/*

publish:
	twine upload dist/*

ghcr_build:
	docker build -t $(GHCR_FULLNAME) .

ghcr_tag:
	docker tag $(GHCR_FULLNAME):latest $(GHCR_FULLNAME):$(VERSION)

ghcr_push:
	docker push $(GHCR_FULLNAME):$(VERSION)
	docker push $(GHCR_FULLNAME):latest

ghcr_all: ghcr_build ghcr_tag ghcr_push

docker_build:
	docker build -t $(DOCKER_FULLNAME) .

docker_tag:
	docker tag $(DOCKER_FULLNAME):latest $(DOCKER_FULLNAME):$(VERSION)

docker_push:
	docker push $(DOCKER_FULLNAME):$(VERSION)
	docker push $(DOCKER_FULLNAME):latest

docker_all: docker_build docker_tag docker_push
