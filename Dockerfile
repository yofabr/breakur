# syntax=docker/dockerfile:1

# ---- build stage ----
FROM golang:1.26-alpine AS build
WORKDIR /src

# cache module downloads separately from source changes
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/breakur ./cmd

# ---- runtime stage ----
FROM alpine:3.20
RUN apk add --no-cache ca-certificates \
    && adduser -D -u 10001 appuser

WORKDIR /app
COPY --from=build /out/breakur /app/breakur
COPY --from=build /src/public /app/public

USER appuser
ENV PORT=8080
EXPOSE 8080

ENTRYPOINT ["/app/breakur"]
