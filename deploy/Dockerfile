FROM golang:1.25-alpine AS build

WORKDIR /src

COPY go.mod go.sum ./
COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o /out/freebeamer-relay ./cmd/freebeamer-relay

FROM alpine:3.22

WORKDIR /app

RUN apk add --no-cache ca-certificates

COPY --from=build /out/freebeamer-relay /app/freebeamer-relay

VOLUME /data
EXPOSE 8080

ENTRYPOINT ["/app/freebeamer-relay"]
CMD ["serve", "--addr", ":8080", "--db", "/data/freebeamer-relay.sqlite"]
