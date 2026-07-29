# * Build Stage
FROM golang:1.25.12-alpine AS builder

LABEL image_author="Michael Prunchak"

WORKDIR /build

RUN apk add --no-cache \
	ca-certificates \
	tzdata

ENV GOTOOLCHAIN=auto

COPY go.mod go.sum ./

RUN go mod download && go mod verify

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
	-ldflags='-w -s -extldflags "-static"' \
	-trimpath \
	-o auth_service \
	./cmd/auth_service

RUN go get github.com/pressly/goose/v3/cmd/goose@v3.27.3 && \
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
	-tags='no_clickhouse no_libsql no_mssql no_mysql no_sqlite3 no_vertica no_ydb' \
	-o /go/bin/goose \
	github.com/pressly/goose/v3/cmd/goose

# * Runtime Stage
FROM alpine:3.20

LABEL maintainer="Michael Prunchak"

WORKDIR /app

RUN apk --no-cache add \
	ca-certificates \
	tzdata \
	&& addgroup -g 1000 appgroup \
	&& adduser -D -u 1000 -G appgroup appuser

COPY --from=builder /build/auth_service .
COPY --from=builder /build/config ./config
COPY --from=builder /build/migrations ./migrations
COPY --from=builder /go/bin/goose /usr/local/bin/goose

USER appuser

EXPOSE 8082

CMD ["./auth_service"]
