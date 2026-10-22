# Build from the tacra/ directory:
#   docker build -f server/Dockerfile .
# The demo RATS-unaware Relying Party is a standalone module; mount its
# rup.json and certificates and point RUP_CONFIG at them.
FROM golang:1.26-alpine AS builder

WORKDIR /src/server
ENV GOWORK=off
COPY server/go.mod server/go.sum ./
RUN go mod download
COPY server/ ./
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /server .

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /server .
EXPOSE 8443
ENTRYPOINT ["./server"]
