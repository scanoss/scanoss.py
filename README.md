# SCANOSS Python Library
The SCANOSS python package provides a simple, easy to consume library for interacting with SCANOSS APIs/Engine.

[![Build/Test Local Package](https://github.com/scanoss/scanoss.py/actions/workflows/python-local-test.yml/badge.svg)](https://github.com/scanoss/scanoss.py/actions/workflows/python-local-test.yml)
[![Build/Test Local Container](https://github.com/scanoss/scanoss.py/actions/workflows/container-local-test.yml/badge.svg)](https://github.com/scanoss/scanoss.py/actions/workflows/container-local-test.yml)
[![Publish Package - PyPI](https://github.com/scanoss/scanoss.py/actions/workflows/python-publish-pypi.yml/badge.svg)](https://github.com/scanoss/scanoss.py/actions/workflows/python-publish-pypi.yml)
[![Publish GHCR Container](https://github.com/scanoss/scanoss.py/actions/workflows/container-publish-ghcr.yml/badge.svg)](https://github.com/scanoss/scanoss.py/actions/workflows/container-publish-ghcr.yml)

# Installation
To install (from [pypi.org](https://pypi.org/project/scanoss)), please run:
```bash
pip3 install scanoss
```

## Usage
The package can be run from the command line, or consumed from another Python script.

For more details, please look at [PACKAGE.md](PACKAGE.md).

## Container Usage
To leverage the CLI from within a container, please look at [GHCR.md](GHCR.md).

## Development
Before starting with development of this project, please read our [CONTRIBUTING](CONTRIBUTING.md) and [CODE OF CONDUCT](CODE_OF_CONDUCT.md).

### Requirements
Python 3.7 or higher.

The dependencies can be found in the [requirements.txt](requirements.txt) and [requirements-dev.txt](requirements-dev.txt) files.

To install dependencies, run:
```bash
pip3 install -r requirements.txt
pip3 install -r requirements-dev.txt
```

To enable dependency scanning, an extra tool is required: scancode-toolkit
```bash
pip3 install -r requirements-scancode.txt
```

### Package Development
More details on Python packaging/distribution can be found [here](https://packaging.python.org/overview/), [here](https://packaging.python.org/guides/distributing-packages-using-setuptools/), and [here](https://packaging.python.org/guides/using-testpypi/#using-test-pypi).

It is good practice to set up a Virtual Env ([venv](https://docs.python.org/3/library/venv.html)) to isolate and simplify development/testing.
If using PyCharm, please follow [these instructions](https://www.jetbrains.com/help/pycharm/creating-virtual-environment.html).

In order to develop/test a Python package, it is necessary to register the package locally. This can be done using the following command:
```bash
python3 setup.py develop --user
```
There is also a [Makefile](Makefile) in the repository, which provide helpers to achieve this:
```bash
make dev_setup
```
The client now makes use of REST & gRPC. For gRPC specific environment variables please look [here](https://github.com/grpc/grpc/blob/master/doc/environment_variables.md).

### Package Deployment
Packaging the library for deployment is done using [setup](https://docs.python.org/3/distutils/setupscript.html).

#### Versioning
The version of the package is defined in the [scanoss init](src/scanoss/__init__.py) file. Please update this version before packaging/releasing an update.

#### Packaging
To package the library, please run:
```bash
make dist
```

#### Deployment
This project uses [twine](https://twine.readthedocs.io/en/latest/) to upload packages to [pypi.org](https://pypi.org).
In order to run twine, a user needs to be registered with both [TestPyPI](https://test.pypi.org) and [PyPI](https://pypi.org).
Details for using TestPyPI can be found [here](https://packaging.python.org/guides/using-testpypi) and PyPI [here](https://packaging.python.org/guides/distributing-packages-using-setuptools/#uploading-your-project-to-pypi).

Once the credentials have been stored in $HOME/.pypirc, the following command can be run:
```bash
make publish_test
```
This will deploy the package to [TestPyPI](https://test.pypi.org/project/scanoss). Run some tests to verify everything is ok.

Then deploy to prod:
```bash
make publish
```
This will deploy the package to [PyPI](https://pypi.org/project/scanoss).

The package will then be available to install using:
```bash
pip3 install scanoss
```

##### GitHub Actions
There are a number of [workflows](.github/workflows) setup for this repository. They provide the following:
* [Local build/test](.github/workflows/python-local-test.yml)
  * Automatically triggered on pushes or PRs to main. Can also be run manually for other branches
* [Local container build/test](.github/workflows/container-local-test.yml)
  * Automatically triggered on pushes or PRs to main. Can also be run manually for other branches
* [Publish to Test PyPI](.github/workflows/python-publish-testpypi.yml)
  * Can be manually triggered to push a test version from any branch
* [Publish to PyPI](.github/workflows/python-publish-pypi.yml)
  * Build and publish the Python package to PyPI (triggered by v*.*.* tag)
* [Publish container to GHCR](.github/workflows/container-publish-ghcr.yml)
  * Build and publish the Python container to GHCR (triggered by v*.*.* tag)

## Bugs/Features
To request features or alert about bugs, please do so [here](https://github.com/scanoss/scanoss.py/issues).

## Changelog
Details of major changes to the library can be found in [CHANGELOG.md](CHANGELOG.md).

## Background
Details about the Winnowing algorithm used for scanning can be found [here](WINNOWING.md).
