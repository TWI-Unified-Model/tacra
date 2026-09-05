# Build from the twium/ directory:
#   docker build -f server/Dockerfile .
FROM golang:1.26-alpine AS builder

WORKDIR /src
COPY go.work go.work.sum ./
COPY server/ server/
COPY cai/ cai/
COPY platform/ platform/
COPY gen/go/ gen/go/

WORKDIR /src/server
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /server .

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /server .
EXPOSE 8443 9090
ENTRYPOINT ["./server"]
