# Builder Image
# ---------------------------------------------------
FROM golang:1.25-alpine AS go-builder

ARG VERSION=dev \
  COMMIT=none

WORKDIR /usr/src/app

COPY . ./

RUN go mod download \
  && CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" -trimpath -a -o main .


# Final Image
# ---------------------------------------------------
FROM dimaskiddo/alpine:base-glibc
MAINTAINER Dimas Restu Hidayanto <dimas.restu@student.upi.edu>

ARG SERVICE_NAME="lmd-ng"

ENV PATH $PATH:/usr/app/${SERVICE_NAME}

WORKDIR /usr/app/${SERVICE_NAME}

RUN apk --no-cache --update upgrade \
  && mkdir -p \
  logs \
  sigs

COPY --from=go-builder /usr/src/app/main ./lmd-ng
COPY --from=go-builder /usr/src/app/config.yaml.example ./config.yaml

CMD ["lmd-ng", "daemon", "--config", "./config.yaml"]
