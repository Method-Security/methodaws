FROM alpine:3.20
ARG TARGETARCH

RUN apk update && apk add --no-cache bash jq ca-certificates

# Setup Method Directory Structure
RUN \
  mkdir -p /opt/method/methodaws/ && \
  mkdir -p /opt/method/methodaws/var/data && \
  mkdir -p /opt/method/methodaws/var/data/tmp && \
  mkdir -p /opt/method/methodaws/var/conf && \
  mkdir -p /opt/method/methodaws/var/log && \
  mkdir -p /opt/method/methodaws/service/bin && \
  mkdir -p /mnt/output

COPY "dist/build-linux_linux_${TARGETARCH}*/methodaws" /opt/method/methodaws/service/bin/methodaws

RUN \
  adduser --disabled-password --gecos '' method && \
  chown -R method:method /opt/method/methodaws/ && \
  chown -R method:method /mnt/output

USER method

WORKDIR /opt/method/methodaws/

ENV PATH="/opt/method/methodaws/service/bin:${PATH}"
