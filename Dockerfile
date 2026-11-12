# syntax=docker/dockerfile:1.29

# Build on the build machine while targeting the requested image platform.
FROM --platform=$BUILDPLATFORM golang:1.27.4 AS build

ENV CGO_ENABLED=0
WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
  go mod download

ARG TARGETOS=linux
ARG TARGETARCH
ARG VERSION=dev

COPY cmd/ ./cmd/
COPY internal/ ./internal/

RUN --mount=type=cache,target=/go/pkg/mod \
  --mount=type=cache,target=/root/.cache/go-build \
  GOOS=$TARGETOS GOARCH=$TARGETARCH \
  go build -trimpath \
  -ldflags="-s -w -X main.Version=${VERSION}" \
  -o /hookglass ./cmd/hookglass

FROM gcr.io/distroless/static:nonroot

COPY --from=build /hookglass /hookglass

ENV HOME=/tmp \
  HOOKGLASS__LISTEN_ADDRESS=:8080

USER 65532:65532

ENTRYPOINT ["/hookglass"]
