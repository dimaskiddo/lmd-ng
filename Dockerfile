# Builder Image
# ---------------------------------------------------
FROM golang:1.25-alpine AS go-builder

ARG VERSION=dev
ARG COMMIT=none

ENV ZIG_VERSION="0.15.2"

WORKDIR /usr/src/app

COPY . ./

RUN mkdir -p /usr/local/zig \
  && wget -O /tmp/zig.tar.xz \
      https://ziglang.org/download/${ZIG_VERSION}/zig-x86_64-linux-${ZIG_VERSION}.tar.xz \
  && tar -xf /tmp/zig.tar.xz -C /usr/local/zig --no-same-owner --strip-component 1 \
  && chmod 755 /usr/local/zig/zig \
  && rm -f /tmp/zig.tar.xz

ENV PATH=${PATH}:/usr/local/zig

RUN go mod download \
  && ZIG_LIBC=musl \
      CC="/usr/src/app/hack/zcc.sh" \
      CXX="/usr/src/app/hack/zcxx.sh" \
      CGO_ENABLED=0 \
      GOOS=linux \
      go build \
        -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" \
        -trimpath -a -o main ./cmd/lmd-ng


# Final Image
# ---------------------------------------------------
FROM dimaskiddo/alpine:base-glibc
MAINTAINER Dimas Restu Hidayanto <drh.dimasrestu@gmail.com>

ARG SERVICE_NAME="lmd-ng"

ENV PATH $PATH:/usr/app/${SERVICE_NAME}

WORKDIR /usr/app/${SERVICE_NAME}

RUN apk --no-cache --update upgrade \
  && mkdir -p \
      logs \
      certs \
      sigs \
      clamav \
      quarantine

COPY --from=go-builder /usr/src/app/main ./lmd-ng
COPY --from=go-builder /usr/src/app/config.yaml.example ./config.yaml

RUN sed -i -e '/- "\/var\/www"/d' ./config.yaml \
    && sed -i -e 's/"\/home"/"\/data"/' ./config.yaml

CMD ["lmd-ng", "daemon", "--config", "./config.yaml"]
