FROM alpine:3.2
ADD explorer-web /explorer-web
ADD templates /templates
WORKDIR /
ENTRYPOINT [ "/explorer-web" ]
