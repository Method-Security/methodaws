FROM cgr.dev/chainguard/static:latest
COPY methodaws /
ENTRYPOINT [ "/methodaws" ]
