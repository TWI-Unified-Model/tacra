# Build from the tacra/ directory:
#   docker build -f cai/Dockerfile .
FROM golang:1.26-alpine AS builder

WORKDIR /src
COPY cai/ cai/
COPY platform/ platform/
COPY gen/go/ gen/go/

WORKDIR /src/cai
ENV GOWORK=off
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /cai ./cmd/sidecar

FROM alpine:latest
WORKDIR /root/
COPY --from=builder /cai .
EXPOSE 50051
ENTRYPOINT ["./cai"]
