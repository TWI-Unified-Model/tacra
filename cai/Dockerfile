# Build from the tacra/ directory:
#   docker build -f cai/Dockerfile .
FROM golang:1.26-alpine AS builder

WORKDIR /src
COPY cai/ cai/
COPY container/ container/
COPY platform/ platform/
COPY gen/go/ gen/go/

# go.sum is not kept in this repository: with -mod=mod the go command verifies
# every module against the checksum database and writes the sums itself.
ENV GOWORK=off GOFLAGS=-mod=mod CGO_ENABLED=0 GOOS=linux

WORKDIR /src/cai
RUN go build -ldflags="-w -s" -o /cai ./cmd/sidecar
# The reporter of the calls of CAAPI that the sidecar records (CAI_TRACE_DIR).
RUN go build -ldflags="-w -s" -o /caapi-trace ./cmd/caapi-trace

# The tool of the simulated platform: it creates the Attestation Key and writes
# the Endorsements of that key and of the measurement of the sidecar.
WORKDIR /src/platform/sim
RUN go build -ldflags="-w -s" -o /tacra-sim-platform ./cmd/tacra-sim-platform

FROM alpine:latest
WORKDIR /root/
COPY --from=builder /cai .
COPY --from=builder /tacra-sim-platform /usr/local/bin/tacra-sim-platform
COPY --from=builder /caapi-trace /usr/local/bin/caapi-trace
EXPOSE 50051
ENTRYPOINT ["./cai"]
