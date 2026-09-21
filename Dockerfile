# syntax=docker/dockerfile:1
# Gateway service image: builds the shell web UI, embeds it (-tags shell), and
# produces a slim runtime carrying gatewaysvc. Build context is the repo root so
# the module's replace directives (../.. , ../auth, ../lcm) resolve.

FROM node:22-alpine AS ui
WORKDIR /ui
COPY services/gateway/shell/package.json services/gateway/shell/package-lock.json* ./
RUN npm ci --no-audit --no-fund || npm install --no-audit --no-fund
COPY services/gateway/shell/ ./
RUN npm run build

FROM golang:1.26-alpine AS build
RUN apk add --no-cache git ca-certificates
WORKDIR /src
COPY . .
COPY --from=ui /ui/dist ./services/gateway/shell/dist
WORKDIR /src/services/gateway
ENV CGO_ENABLED=0 GOFLAGS=-buildvcs=false
RUN go build -tags "shell" -o /out/gatewaysvc ./cmd/gatewaysvc

FROM alpine:3.20
RUN apk add --no-cache ca-certificates postgresql-client && adduser -D -u 10001 app
COPY --from=build /out/gatewaysvc /usr/local/bin/
COPY services/gateway/deploy /app/deploy
WORKDIR /app
USER app
ENTRYPOINT ["gatewaysvc"]
CMD ["-config", "deploy/dev.yaml"]
