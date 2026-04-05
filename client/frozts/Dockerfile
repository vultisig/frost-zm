FROM rust:1.83-bookworm AS rust-builder

WORKDIR /build
COPY frosty-lib/Cargo.toml frosty-lib/Cargo.lock frosty-lib/rust-toolchain.toml ./
COPY frosty-lib/crates/ crates/

RUN cargo build --release -p frozts-lib

FROM golang:1.24-bookworm AS go-builder

COPY --from=rust-builder /build/target/release/libfroztslib.so /usr/lib/
RUN ldconfig

WORKDIR /build/frosty-lib
COPY frosty-lib/go/ go/
COPY frosty-lib/client/shared/ client/shared/
COPY frosty-lib/client/frozts/ client/frozts/
COPY commondata/ /build/commondata/

COPY --from=rust-builder /build/crates/frozts-lib/include/frozts-lib.h go/frozts/includes/
RUN ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "amd64" ]; then LIBDIR=linux-amd64; else LIBDIR=linux-arm64; fi && \
    mkdir -p go/frozts/includes/$LIBDIR && \
    cp /usr/lib/libfroztslib.so go/frozts/includes/$LIBDIR/

WORKDIR /build/frosty-lib/client/frozts
RUN CGO_ENABLED=1 go build -o /frozts-party ./cmd/frozts-party

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=rust-builder /build/target/release/libfroztslib.so /usr/lib/
RUN ldconfig

COPY --from=go-builder /frozts-party /usr/local/bin/frozts-party

RUN mkdir -p /data/keystore

ENTRYPOINT ["frozts-party"]
