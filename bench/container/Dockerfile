# Test image with the WAMP router and the wamp_load generator (Linux x86_64, e.g. ECS Fargate). This is
# tooling for load tests and CPU-limit checks, not a production deployment (it generates a throwaway certificate).
# Build the binaries first (Release) and copy them to bench/container/bin/ (docker build -f bench/container/Dockerfile .): ./scripts/cmake-build.sh && ./scripts/run.sh cmake --build build --target wamp_load wamp_profile_router
FROM ubuntu:24.04

RUN apt-get update -qq \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
        libc++1-18 libc++abi1-18 libssl3t64 openssl ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

COPY bench/container/bin/wamp_router bench/container/bin/wamp_profile_router bench/container/bin/wamp_load /opt/wamp/
COPY bench/container/entrypoint.sh /opt/wamp/entrypoint.sh
RUN chmod +x /opt/wamp/entrypoint.sh && useradd --system --home /opt/wamp wamp

USER wamp
WORKDIR /opt/wamp
EXPOSE 8080
ENTRYPOINT ["/opt/wamp/entrypoint.sh"]
