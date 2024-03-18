FROM --platform=$BUILDPLATFORM python:3.10-slim-buster as base

LABEL maintainer="SCANOSS <infra@scanoss.com>"
LABEL org.opencontainers.image.source=https://github.com/scanoss/scanoss.py
LABEL org.opencontainers.image.description="SCANOSS Python CLI Container"
LABEL org.opencontainers.image.licenses=MIT

FROM base as builder

# Setup the required build tooling
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential gcc \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

RUN mkdir /install
WORKDIR /install
ENV PATH=/root/.local/bin:$PATH

COPY ./dist/scanoss-*-py3-none-any.whl /install/

# Install dependencies
RUN pip3 install --user /install/scanoss-*-py3-none-any.whl
RUN pip3 install --user scanoss_winnowing
RUN pip3 install --user scancode-toolkit-mini
#RUN pip3 install --user typecode-libmagic

# Download compile and install typecode-libmagic from source (as there is not ARM wheel available)
ADD https://github.com/nexB/typecode_libmagic_from_sources/archive/refs/tags/v5.39.210212.tar.gz /install/
RUN tar -xvzf /install/v5.39.210212.tar.gz -C /install \
    && cd /install/typecode_libmagic_from_sources* \
    && ./build.sh && python3 setup.py sdist bdist_wheel \
    && pip3 install --user `ls /install/typecode_libmagic_from_sources*/dist/*.whl`

# Remove license data references as they are not required for dependency scanning (to save space)
RUN rm -rf /root/.local/lib/python3.10/site-packages/licensedcode/data/rules /root/.local/lib/python3.10/site-packages/licensedcode/data/cache
RUN mkdir  /root/.local/lib/python3.10/site-packages/licensedcode/data/rules /root/.local/lib/python3.10/site-packages/licensedcode/data/cache

FROM base

# Copy the Python user packages from the build image to here
COPY --from=builder /root/.local /root/.local
# Setup the path and explicitly set GRPC Polling strategy
ENV PATH=/root/.local/bin:$PATH
ENV GRPC_POLL_STRATEGY=poll

RUN apt-get update \
 && apt-get install -y --no-install-recommends jq curl \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

VOLUME /scanoss
WORKDIR /scanoss

# Run scancode once to setup any initial files, etc. so that it'll run faster later
RUN scancode -p --only-findings --quiet --json /scanoss/scancode-dependencies.json /scanoss && rm -f /scanoss/scancode-dependencies.json

ENTRYPOINT ["scanoss-py"]
CMD ["--help"]
