FROM rust:slim-trixie AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock build.rs ./
COPY src ./src
RUN cargo build --release --bins --locked -j2

FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends btrfs-progs && \
    rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/dduper /usr/local/sbin/dduper
COPY --from=build /src/target/release/dduper-btrfs /usr/local/sbin/dduper-btrfs
ENTRYPOINT ["/usr/local/sbin/dduper"]
