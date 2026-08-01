# syntax=docker/dockerfile:1

FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/asb-a2a ./examples/a2a-multiprocess
RUN mkdir -p /out/state/manager /out/state/attester /out/state/verifier /out/state/replay /out/state/agent-a /out/state/agent-b

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/asb-a2a /asb-a2a
COPY --from=build --chown=65532:65532 /out/state /state
ENTRYPOINT ["/asb-a2a"]
