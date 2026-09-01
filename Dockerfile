# Multi-arch capable: build with
#   docker buildx build --platform linux/amd64,linux/arm64 -t <registry>/pr60x-exporter:<tag> --push .
# A mixed amd64/arm64 cluster needs both, or the pod will only schedule on
# whichever architecture the image was built for.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build

ARG TARGETOS
ARG TARGETARCH

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY internal/ ./internal/
COPY cmd/ ./cmd/

# CGO off so the binary runs on a distroless/static base.
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/pr60x-exporter ./cmd/pr60x-exporter

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/pr60x-exporter /pr60x-exporter
EXPOSE 9812
USER nonroot:nonroot
ENTRYPOINT ["/pr60x-exporter"]
