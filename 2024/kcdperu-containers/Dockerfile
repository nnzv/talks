# Copyright 2024 Enzo Venturi. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

## Stage 1 (source)
# Copy and build source code
FROM docker.io/library/golang:1.22-alpine AS src

WORKDIR /app

ENV CGO_ENABLED 0

COPY . .

RUN go build -ldflags="-w -s" -o kcd

## Stage 2 (developemnt): default
# Copy and run app from 'src' stage
FROM docker.io/library/alpine:latest AS dev

COPY --from=src /app/kcd .

ENTRYPOINT ["/kcd"]
