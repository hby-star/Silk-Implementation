FROM rust:1.96-bookworm AS builder
WORKDIR /workspace
COPY . .
ARG SILK_BUILD_GIT_COMMIT
ARG SILK_BUILD_GIT_DIRTY
ARG SILK_BUILD_SOURCE_FINGERPRINT
RUN SILK_BUILD_GIT_COMMIT="${SILK_BUILD_GIT_COMMIT}" \
    SILK_BUILD_GIT_DIRTY="${SILK_BUILD_GIT_DIRTY}" \
    SILK_BUILD_SOURCE_FINGERPRINT="${SILK_BUILD_SOURCE_FINGERPRINT}" \
    cargo build --release --workspace --locked

FROM debian:trixie-slim
ARG SILK_BUILD_GIT_COMMIT
ARG SILK_BUILD_GIT_DIRTY
ARG SILK_BUILD_SOURCE_FINGERPRINT
LABEL org.silk.build.git-commit="${SILK_BUILD_GIT_COMMIT}" \
      org.silk.build.git-dirty="${SILK_BUILD_GIT_DIRTY}" \
      org.silk.build.source-fingerprint="${SILK_BUILD_SOURCE_FINGERPRINT}"
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 iputils-ping iperf3 ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /workspace/target/release/experiment-runner /usr/local/bin/experiment-runner
COPY --from=builder /workspace/experiments /workspace/experiments
COPY experiments/docker/entrypoint.sh /usr/local/bin/silk-docker-entrypoint
RUN chmod 0555 /usr/local/bin/silk-docker-entrypoint && mkdir -p /run /results /state
WORKDIR /workspace
ENTRYPOINT ["/usr/local/bin/silk-docker-entrypoint"]
