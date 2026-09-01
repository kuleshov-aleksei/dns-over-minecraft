FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /dnsmc ./cmd/dnsmc

FROM scratch
COPY --from=builder /dnsmc /dnsmc
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
EXPOSE 25565
ENTRYPOINT ["/dnsmc"]
CMD ["-S", "-config", "/config.yaml"]
