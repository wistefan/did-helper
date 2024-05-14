FROM golang:1.21-alpine AS build


WORKDIR /go/src/app
COPY ./ ./
RUN go get -d -v ./...
RUN go build -v .

FROM ubuntu

ENV COUNTRY="DE"
ENV STATE="Saxony"
ENV LOCALITY="Dresden"
ENV ORGANIZATION="FIWARE Foundation e.V."
ENV COMMON_NAME="www.fiware.org"
ENV STORE_PASS="myPassword"
ENV KEY_ALIAS="myAlias"
ENV OUTPUT_FORMAT="json"
ENV OUTPUT_FILE="/cert/did.json"


RUN apt-get update
RUN apt-get install openssl -yq
RUN apt-get install wget -yq

RUN mkdir /cert
RUN mkdir /did-helper
RUN chmod a+rw /cert
RUN chmod a+rw /did-helper

WORKDIR /did-helper

COPY --from=build /go/src/app/did-helper ./did-helper
COPY --from=build /go/src/app/docker/entrypoint.sh /temp/entrypoint.sh

RUN chmod a+x /temp/entrypoint.sh
USER 1000
ENTRYPOINT ["/temp/entrypoint.sh"]