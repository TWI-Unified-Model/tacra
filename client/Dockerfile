# Build from the tacra/ directory:
#   docker build -f client/Dockerfile .
FROM golang:1.26-alpine AS builder

WORKDIR /src
COPY client/ client/
COPY gen/go/ gen/go/

WORKDIR /src/client
# go.sum is not kept in this repository: with -mod=mod the go command verifies
# every module against the checksum database and writes the sums itself.
ENV GOWORK=off GOFLAGS=-mod=mod
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /client .

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /client .
ENTRYPOINT ["./client"]
