# syntax=docker/dockerfile:1

# ---- build stage: compile a static binary with embedded assets ----
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/hermad .

# ---- production runtime: minimal image, runs the binary as a non-root user ----
FROM alpine:3.20 AS prod
RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -S hermad && adduser -S -G hermad -u 10001 hermad
WORKDIR /app
COPY --from=build /out/hermad /app/hermad
ENV HERMAD_DATA_DIR=/data HERMAD_LISTEN=:8080
USER hermad
EXPOSE 8080
ENTRYPOINT ["/app/hermad"]

# ---- development: live reload via air, source bind-mounted by compose ----
FROM golang:1.26-alpine AS dev
RUN apk add --no-cache git && go install github.com/air-verse/air@latest
WORKDIR /src
ENV HERMAD_DATA_DIR=/data HERMAD_LISTEN=:8080
EXPOSE 8080
CMD ["air", "-c", ".air.toml"]
