ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown

FROM golang:1.26-alpine AS builder
ARG VERSION
ARG COMMIT
ARG DATE
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags "-X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" -o /dnsmc ./cmd/dnsmc

FROM scratch
COPY --from=builder /dnsmc /dnsmc
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
USER 1000:1000
EXPOSE 25565
STOPSIGNAL SIGTERM
ENTRYPOINT ["/dnsmc"]
CMD ["-S", "-config", "/config.yaml"]