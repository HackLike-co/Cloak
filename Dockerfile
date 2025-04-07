FROM golang:1.24-bookworm

WORKDIR /cloak

COPY cloak /cloak/cloak
COPY api /cloak/api
COPY images /cloak/images
COPY static /cloak/static
COPY main.go /cloak/main.go
COPY go.sum /cloak/go.sum
COPY go.mod /cloak/go.mod

RUN apt update && \
    apt install -y mingw-w64 make

RUN go build .


EXPOSE 8080

CMD ["/cloak-ui"]