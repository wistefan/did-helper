FROM golang:1.23-alpine AS build


WORKDIR /go/src/app
COPY ./ ./
RUN go get -d -v ./...
RUN go build -v .

FROM ubuntu

ENV KEY_TYPE_TO_GENERATE="EC"


ENV COUNTRY="DE"
ENV STATE="Saxony"
ENV LOCALITY="Dresden"
ENV ORGANIZATION="M&P Operations Inc."
ENV COMMON_NAME="www.mp-operations.org"
ENV STORE_PASS="myPassword"
ENV KEY_ALIAS="myAlias"
ENV KEY_TYPE="P-256"
ENV OUTPUT_FORMAT="json"
ENV DID_TYPE="key"
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
ENTRYPOINT ["/temp/entrypoint.sh"]