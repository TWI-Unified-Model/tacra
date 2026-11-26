# Build from the tacra/ directory:
#   docker build -f server/Dockerfile .
# The demo RATS-unaware Relying Party is a standalone module; mount its
# rup.json and certificates and point RUP_CONFIG at them.
FROM golang:1.26-alpine AS builder

WORKDIR /src/server
# go.sum is not kept in this repository: with -mod=mod the go command verifies
# every module against the checksum database and writes the sums itself.
ENV GOWORK=off GOFLAGS=-mod=mod
COPY server/ ./
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /server .

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /server .
EXPOSE 8443
ENTRYPOINT ["./server"]
