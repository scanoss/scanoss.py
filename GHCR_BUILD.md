# SCANOSS Python GitHub Container Repo
The SCANOSS python package provides a simple, easy to consume library for interacting with SCANOSS APIs/Engine.

## Usage
The image can be run from the command line, or from within a pipeline.

For more details, please look in [GHCR.md](GHCR.md).

## Development
Before starting with development of this project, please read our [CONTRIBUTING](CONTRIBUTING.md) and [CODE OF CONDUCT](CODE_OF_CONDUCT.md).

### Requirements
Docker client needs to be installed locally.

A login to GitHub Packages is also needed, should you wish to publish the image.
Details of generating a personal access token can be found [here](https://docs.github.com/en/packages/learn-github-packages/about-permissions-for-github-packages).

### Repo Development
More details on Docker build/deployment can be found [here](https://docs.docker.com/get-started/).

### Build
To build a local image from the [Dockerfile](Dockerfile) please use:
```bash
make ghcr_build
```
To test this image please run:
```bash
docker run -it ghcr.io/scanoss/scanoss-py 
```
For more details execution options, please look in [GHCR.md](GHCR.md).

#### Versioning
The version of the package is defined in the [scanoss init](src/scanoss/__init__.py) file. Please update this version before packaging/releasing an update.

To tag the latest build, please run:
```bash
make ghcr_tag
```

#### Deployment
In order to deploy the image, a user needs to generate a [personal access token](https://github.com/settings/tokens) (PAT) on GitHub. More details [here](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry).

Then login using:
```bash
export CR_PAT=YOUR_TOKEN
echo $CR_PAT | docker login ghcr.io -u USERNAME --password-stdin
```
And push the image using:
```bash
make ghcr_push
```
This will deploy the image to [GHCR](https://github.com/scanoss/scanoss.py/pkgs/container/scanoss-py/versions).

The image will then be available to install using:
```bash
docker pull ghcr.io/scanoss/scanoss-py:latest
```

## Bugs/Features
To request features or alert about bugs, please do so [here](https://github.com/scanoss/scanoss.py/issues).

## Changelog
Details of major changes to the library can be found in [CHANGELOG.md](CHANGELOG.md).
