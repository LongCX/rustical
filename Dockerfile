FROM rust:1.90-alpine AS chef

RUN echo x86_64-unknown-linux-musl > /tmp/rust_target

RUN apk add --no-cache musl-dev llvm20 clang perl pkgconf make \
  && rustup target add "$(cat /tmp/rust_target)" \
  && cargo install cargo-chef --locked \
  && rm -rf "$CARGO_HOME/registry"

WORKDIR /rustical

FROM chef AS planner
COPY . .
RUN cargo chef prepare

FROM chef AS builder

WORKDIR /rustical
COPY --from=planner /rustical/recipe.json recipe.json
RUN cargo chef cook --release --target "$(cat /tmp/rust_target)"

COPY . .
RUN cargo install --target "$(cat /tmp/rust_target)" --path .

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --chown=nonroot:nonroot --from=builder /usr/local/cargo/bin/rustical /app/rustical

USER nonroot

ENV TZ=Asia/Ho_Chi_Minh
ENV RUSTICAL_DATA_STORE__SQLITE__DB_URL=/etc/rustical/db.sqlite3

VOLUME ["/etc/rustical"]
EXPOSE 4000

CMD ["/app/rustical"]
