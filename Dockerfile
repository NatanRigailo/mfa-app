FROM golang:1.24-alpine AS builder

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o mfa-app .

FROM alpine:3.21

RUN apk add --no-cache su-exec \
    && addgroup -S appgroup && adduser -S appuser -G appgroup

COPY --from=builder /build/mfa-app   /app/mfa-app
COPY --from=builder /build/templates /app/templates
COPY --from=builder /build/static    /app/static
COPY entrypoint.sh                   /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

WORKDIR /app

VOLUME ["/data"]
EXPOSE 5000

ENTRYPOINT ["/app/entrypoint.sh"]
