FROM chainguard/static:latest
COPY methodaws /
RUN mkdir -p /mnt/output
ENTRYPOINT [ "/methodaws" ]
