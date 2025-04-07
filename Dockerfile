FROM golang:1.24-bookworm

WORKDIR /cloak

COPY . .

RUN apt update && \
    apt install -y mingw-w64 make

RUN go build .

EXPOSE 8080

CMD ["./cloak-ui"]