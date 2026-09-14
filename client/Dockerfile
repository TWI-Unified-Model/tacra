# Build from the tacra/ directory:
#   docker build -f client/Dockerfile .
FROM golang:1.26-alpine AS builder

WORKDIR /src
COPY client/ client/
COPY gen/go/ gen/go/

WORKDIR /src/client
ENV GOWORK=off
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /client .

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /client .
ENTRYPOINT ["./client"]
