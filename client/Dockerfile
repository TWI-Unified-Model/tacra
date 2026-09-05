# Build from the twium/ directory:
#   docker build -f client/Dockerfile .
FROM golang:1.26-alpine AS builder

WORKDIR /src
COPY go.work go.work.sum ./
COPY client/ client/
COPY cai/ cai/
COPY platform/ platform/
COPY gen/go/ gen/go/

WORKDIR /src/client
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /client .

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /client .
ENTRYPOINT ["./client"]
