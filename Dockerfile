FROM chainguard/static:latest
COPY methodaws /
ENTRYPOINT [ "/methodaws" ]
