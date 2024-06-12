FROM alpine:3.19.1 as base
LABEL maintainer="sam@method.security"
ARG TARGETARCH

RUN apk update && apk add bash jq

# Setup Method Directory Structure
RUN \
  mkdir -p /opt/method/methodaws/ && \
  mkdir -p /opt/method/methodaws/var/data && \
  mkdir -p /opt/method/methodaws/var/data/tmp && \
  mkdir -p /opt/method/methodaws/var/conf && \
  mkdir -p /opt/method/methodaws/var/log && \
  mkdir -p /opt/method/methodaws/service/bin && \
  mkdir -p /mnt/output

COPY scripts/* /opt/method/methodaws/service/bin/

FROM base as amd64
COPY build/linux-amd64/methodaws /opt/method/methodaws/service/bin/methodaws

FROM base as arm64
COPY build/linux-arm64/methodaws /opt/method/methodaws/service/bin/methodaws

FROM ${TARGETARCH} as final

RUN \
  adduser --disabled-password --gecos '' method && \
  chown -R method:method /opt/method/methodaws/ && \
  chown -R method:method /mnt/output
USER method
WORKDIR /opt/method/methodaws/
ENV PATH="/opt/method/methodaws/service/bin:${PATH}"
