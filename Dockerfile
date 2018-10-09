#
# Build
#

FROM  golang:stretch as builder

ARG   ROOT_IMPORT_PATH
ARG   CMD_REL_PATH
ARG   BUILD_VERSION=v0.0.0

COPY  . /go/src/${ROOT_IMPORT_PATH}

WORKDIR /go/src/${ROOT_IMPORT_PATH}

RUN   go build -tags netgo -ldflags="-s -w -X ${ROOT_IMPORT_PATH}.Version=${BUILD_VERSION}" -o app ${CMD_REL_PATH}


#
# Main Image
#

FROM  scratch

LABEL maintainer="John Weldon <johnweldon4@gmail.com>" \
      company="John Weldon Consulting"

ARG   ROOT_IMPORT_PATH

COPY  --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY  --from=builder /go/src/${ROOT_IMPORT_PATH}/app /app
COPY  public /public/
COPY  templates /templates/

ENV   PORT 12380
ENV   PUBLIC_DIR /public

ENTRYPOINT ["/app"]
