# Build stage
FROM golang:1.23-alpine AS builder

# Install dependencies for building
RUN apk add --no-cache git make

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN make build

# Final stage
FROM alpine:latest

# Install ca-certificates for HTTPS
RUN apk --no-cache add ca-certificates

WORKDIR /root/

# Copy the binary from builder stage
COPY --from=builder /app/bin/cartographer .

# Make it executable
RUN chmod +x ./cartographer

# Create a non-root user
RUN adduser -D -s /bin/sh cartographer

USER cartographer

# Command to run
ENTRYPOINT ["./cartographer"]
