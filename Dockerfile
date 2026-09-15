FROM rust:bookworm AS build
WORKDIR /src
RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config \
    && rm -rf /var/lib/apt/lists/*
COPY rust-toolchain.toml Cargo.toml Cargo.lock ./
COPY .cargo .cargo
COPY src src
# repo config defaults to musl; GNU is enough inside Debian.
RUN cargo build --release --target x86_64-unknown-linux-gnu

FROM debian:bookworm-slim
WORKDIR /data
COPY --from=build /src/target/x86_64-unknown-linux-gnu/release/mc-scan /usr/local/bin/mc-scan
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/mc-scan"]
CMD ["--listen", "0.0.0.0:8080"]
