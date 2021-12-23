FROM python:3.8-slim-buster

LABEL maintainer="SCANOSS <infra@scanoss.com>"

RUN pip3 install scanoss

VOLUME /scanoss
WORKDIR /scanoss

ENTRYPOINT ["scanoss-py"]
CMD ["--help"]
