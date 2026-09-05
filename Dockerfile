# Builds ONE of the exporters in cmd/, selected by the EXPORTER build arg.
#
# Multi-arch capable, and that matters rather than being a nicety: a mixed
# amd64/arm64 cluster will happily schedule the pod onto an arm64 node, and a
# single-arch image just fails to pull there with no obvious clue why.
#
#   docker buildx build --platform linux/amd64,linux/arm64 \
#     --build-arg EXPORTER=xs508tm-exporter \
#     -t <registry>/xs508tm-exporter:<tag> --push .
#
# EXPORTER defaults to pr60x-exporter so an argument-less build keeps doing
# what it always did.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build

ARG TARGETOS
ARG TARGETARCH
ARG EXPORTER=pr60x-exporter

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY internal/ ./internal/
COPY cmd/ ./cmd/

# CGO off so the binary runs on a distroless/static base.
#
# The binary lands at a FIXED path rather than being named after the exporter:
# the image already says which one it is, and a fixed entrypoint means the
# deployment manifests differ only in image and args.
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/exporter ./cmd/${EXPORTER}

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/exporter /exporter
# Documentation only - the real port comes from --listen. pr60x uses 9812,
# xs508tm 9813, so neither is hardcoded here.
EXPOSE 9812 9813
USER nonroot:nonroot
ENTRYPOINT ["/exporter"]
