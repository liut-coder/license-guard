# syntax=docker/dockerfile:1

FROM golang:1.24-bookworm AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -buildvcs=false -o /out/licenseguard-server ./cmd/licenseguard-server \
    && CGO_ENABLED=0 go build -buildvcs=false -o /out/licenseguard-migrate ./cmd/licenseguard-migrate

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --home-dir /var/lib/licenseguard --shell /usr/sbin/nologin licenseguard

WORKDIR /app
COPY --from=build /out/licenseguard-server /usr/local/bin/licenseguard-server
COPY --from=build /out/licenseguard-migrate /usr/local/bin/licenseguard-migrate
COPY web/admin ./web/admin
COPY migrations ./migrations

RUN mkdir -p /var/lib/licenseguard/keys \
    && chown -R licenseguard:licenseguard /var/lib/licenseguard

USER licenseguard
EXPOSE 8090

ENTRYPOINT ["/usr/local/bin/licenseguard-server"]
