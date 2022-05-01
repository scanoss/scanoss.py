FROM python:3.8-slim-buster as base

LABEL maintainer="SCANOSS <infra@scanoss.com>"

FROM base as builder

# Setup the required build tooling
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential gcc \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* \

RUN mkdir /install
WORKDIR /install
ENV PATH=/root/.local/bin:$PATH

COPY ./dist/scanoss-*-py3-none-any.whl /install/

#RUN pip3 install --user scanoss
RUN pip3 install --user /install/scanoss-*-py3-none-any.whl
RUN pip3 install --user scancode-toolkit-mini
RUN pip3 install --user typecode-libmagic

# Remove license data references as they are not required for dependency scanning (to save space)
RUN rm -rf /root/.local/lib/python3.8/site-packages/licensedcode/data/rules /root/.local/lib/python3.8/site-packages/licensedcode/data/cache
RUN mkdir /root/.local/lib/python3.8/site-packages/licensedcode/data/rules /root/.local/lib/python3.8/site-packages/licensedcode/data/cache

FROM base

# Copy the Python user packages from the build image to here
COPY --from=builder /root/.local /root/.local
# Setup the path and explicitly set GRPC Polling strategy
ENV PATH=/root/.local/bin:$PATH
ENV GRPC_POLL_STRATEGY=poll

VOLUME /scanoss
WORKDIR /scanoss

ENTRYPOINT ["scanoss-py"]
CMD ["--help"]
