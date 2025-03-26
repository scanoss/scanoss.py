FROM --platform=$BUILDPLATFORM python:3.10-slim AS base

LABEL maintainer="SCANOSS <infra@scanoss.com>"
LABEL org.opencontainers.image.source=https://github.com/scanoss/scanoss.py
LABEL org.opencontainers.image.description="SCANOSS Python CLI Container"
LABEL org.opencontainers.image.licenses=MIT

# Compile and install all the necessary python requirements
FROM base AS builder

# Setup the required build tooling
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential gcc \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Create and activate virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /install

# assumes `make dist` as prerequisite
COPY ./dist/scanoss-*-py3-none-any.whl /install/
COPY ./requirements-dev.txt /install/

# Install dependencies
RUN pip3 install --no-cache-dir /install/scanoss-*-py3-none-any.whl
RUN pip3 install --no-cache-dir scanoss_winnowing
RUN pip3 install --no-cache-dir -r /install/requirements-dev.txt
RUN pip3 install --no-cache-dir scancode-toolkit-mini

# Download compile and install typecode-libmagic from source (as there is not ARM wheel available)
ADD https://github.com/nexB/typecode_libmagic_from_sources/archive/refs/tags/v5.39.210212.tar.gz /install/
RUN tar -xvzf /install/v5.39.210212.tar.gz -C /install \
    && cd /install/typecode_libmagic_from_sources* \
    && ./build.sh \
    && python3 setup.py sdist bdist_wheel \
    && ls /install/typecode_libmagic_from_sources*/dist/*.whl \
    && pip3 install --no-cache-dir `ls /install/typecode_libmagic_from_sources*/dist/*.whl`

RUN pip3 uninstall --no-cache-dir -y -r /install/requirements-dev.txt

# Remove license data references as they are not required for dependency scanning (to save space)
RUN rm -rf /opt/venv/lib/python3.10/site-packages/licensedcode/data/rules /opt/venv/lib/python3.10/site-packages/licensedcode/data/cache
RUN mkdir  /opt/venv/lib/python3.10/site-packages/licensedcode/data/rules /opt/venv/lib/python3.10/site-packages/licensedcode/data/cache

# Image with no default entry point
FROM base AS no_entry_point

# Copy the Python user packages from the build image to here
COPY --from=builder /opt/venv /opt/venv
# Setup the path and explicitly set GRPC Polling strategy
ENV PATH=/opt/venv/bin:$PATH
ENV GRPC_POLL_STRATEGY=poll

# Install jq and curl commands
RUN apt-get update \
    && apt-get install -y --no-install-recommends jq curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Install syft
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Setup working directory and user
WORKDIR /scanoss
# Run scancode once to setup any initial files, etc. so that it'll run faster later
RUN scancode -p --only-findings --quiet --json /scanoss/scancode-dependencies.json /scanoss && rm -f /scanoss/scancode-dependencies.json

# Image with no default entry point
FROM no_entry_point AS jenkins

# Create scanoss user for compatibility
RUN groupadd -g 1000 jenkins && \
    useradd -u 1000 -g jenkins -m -s /bin/bash jenkins

# Copy the Python user packages from the build image to here
RUN chown -R jenkins:jenkins /scanoss /opt/venv
USER jenkins

# Image with a default scanoss-py entry point
FROM no_entry_point AS with_entry_point

ENTRYPOINT ["scanoss-py"]
CMD ["--help"]
