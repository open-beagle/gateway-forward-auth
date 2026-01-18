#!/bin/bash

set -ex

export GO111MODULE=on
export CGO_ENABLED=0

git config --global --add safe.directory $PWD

GIT_COMMIT=$(git rev-parse --short HEAD)
BUILD_DATE=$(date +%Y-%m-%d_%H:%M:%S)
VERSION=${VERSION:-dev}

LDFLAGS=(
  "-w -s"
  "-X github.com/thomseddon/traefik-forward-auth/internal.Version=${VERSION}"
  "-X github.com/thomseddon/traefik-forward-auth/internal.GitCommit=${GIT_COMMIT}"
  "-X github.com/thomseddon/traefik-forward-auth/internal.BuildDate=${BUILD_DATE}"
)

mkdir -p ./bin

export GOARCH=amd64
go build -ldflags "${LDFLAGS[*]}" -o ./bin/gateway-forward-auth-$GOARCH ./cmd

export GOARCH=arm64
go build -ldflags "${LDFLAGS[*]}" -o ./bin/gateway-forward-auth-$GOARCH ./cmd
