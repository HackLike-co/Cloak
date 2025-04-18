FROM golang:1.24-bookworm

WORKDIR /cloak

COPY . .

RUN apt update && \
    apt install -y mingw-w64 make wget xz-utils && \
    wget https://ziglang.org/download/0.14.0/zig-linux-x86_64-0.14.0.tar.xz && \
    tar -xf zig-linux-x86_64-0.14.0.tar.xz && \
    mv zig-linux-x86_64-0.14.0 /usr/local/zig && \
    rm zig-linux-x86_64-0.14.0.tar.xz;

RUN ln -s /usr/local/zig/zig /usr/local/bin/zig

RUN go build .

EXPOSE 8080

CMD ["./cloak-ui"]