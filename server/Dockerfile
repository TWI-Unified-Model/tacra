# Stage 1: Build binary
FROM golang:1.26-alpine AS builder

WORKDIR /app

COPY go.mod ./
# RUN go mod download # No external dependencies yet, but good practice

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o server main.go

# Stage 2: Minimal runtime container
FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /root/
COPY --from=builder /app/server .

EXPOSE 8080

ENTRYPOINT ["./server"]
