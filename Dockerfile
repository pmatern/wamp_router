# syntax=docker/dockerfile:1.4

# Multi-stage Dockerfile for C++23 Build Container
# Ubuntu 24.04 + Clang 18+ + CMake + Ninja + vcpkg

# Stage 1: Base system with compilers and build tools
FROM ubuntu:24.04 AS base

# Metadata
LABEL maintainer="C++23 Build Container"
LABEL description="C++23 Build Container with Clang 18+, CMake, Ninja, and vcpkg"
LABEL version="1.0.0"

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC

# Install system dependencies in optimized order
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Build essentials with GCC 14 for libstdc++14 (needed for C++23 std::expected)
    build-essential \
    g++-14 \
    libstdc++-14-dev \
    # Clang 18+ and LLVM toolchain
    clang-18 \
    clang-tools-18 \
    clang-format-18 \
    clang-tidy-18 \
    libc++-18-dev \
    libc++abi-18-dev \
    lld-18 \
    lldb-18 \
    # Debuggers for remote debugging
    gdb \
    gdbserver \
    # CMake and Ninja (use latest from Ubuntu 24.04 repos)
    cmake \
    ninja-build \
    # vcpkg dependencies
    curl \
    zip \
    unzip \
    tar \
    git \
    pkg-config \
    # Network libraries and utilities
    libssl-dev \
    # Additional utilities
    ca-certificates \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Set compilers as default
RUN update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-14 100 && \
    update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-14 100 && \
    update-alternatives --install /usr/bin/clang clang /usr/bin/clang-18 100 && \
    update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-18 100 && \
    update-alternatives --install /usr/bin/clang-format clang-format /usr/bin/clang-format-18 100 && \
    update-alternatives --install /usr/bin/clang-tidy clang-tidy /usr/bin/clang-tidy-18 100 && \
    update-alternatives --install /usr/bin/lld lld /usr/bin/lld-18 100

# Verify installations
RUN gcc --version && \
    g++ --version && \
    clang++ --version && \
    cmake --version && \
    ninja --version

# Stage 2: Build and bootstrap vcpkg
FROM base AS vcpkg-builder

# Set vcpkg environment variables
ENV VCPKG_ROOT=/opt/vcpkg
ENV VCPKG_DOWNLOADS=/opt/vcpkg-downloads
ENV VCPKG_DEFAULT_BINARY_CACHE=/opt/vcpkg-cache

# Create vcpkg directories
RUN mkdir -p ${VCPKG_ROOT} ${VCPKG_DOWNLOADS} ${VCPKG_DEFAULT_BINARY_CACHE}

# Clone vcpkg at specific commit for reproducibility
ARG VCPKG_VERSION=2024.11.16
RUN git clone https://github.com/Microsoft/vcpkg.git ${VCPKG_ROOT} && \
    cd ${VCPKG_ROOT} && \
    git checkout ${VCPKG_VERSION}

# Bootstrap vcpkg
RUN ${VCPKG_ROOT}/bootstrap-vcpkg.sh -disableMetrics

# Integrate vcpkg and verify installation
RUN ${VCPKG_ROOT}/vcpkg integrate install && \
    ${VCPKG_ROOT}/vcpkg version

# Stage 3: Final production image
FROM base AS final

# Copy vcpkg from builder stage
COPY --from=vcpkg-builder /opt/vcpkg /opt/vcpkg

# Set environment variables
ENV VCPKG_ROOT=/opt/vcpkg
ENV VCPKG_DOWNLOADS=/opt/vcpkg-downloads
ENV VCPKG_DEFAULT_BINARY_CACHE=/opt/vcpkg-cache
ENV PATH="${VCPKG_ROOT}:${PATH}"

# Configure compiler environment
ENV CC=clang-18
ENV CXX=clang++-18
ENV CXXFLAGS="-stdlib=libc++"
ENV LDFLAGS="-stdlib=libc++ -lc++abi"

# Create directories for vcpkg downloads and cache
# These will be volume mount points for persistence
RUN mkdir -p ${VCPKG_DOWNLOADS} ${VCPKG_DEFAULT_BINARY_CACHE}

# Create workspace directory
RUN mkdir -p /workspace
WORKDIR /workspace

# Set up non-root user for security
ARG USERNAME=builder
ARG USER_UID=1000
ARG USER_GID=1000

RUN if ! getent group ${USER_GID} > /dev/null 2>&1; then \
        groupadd --gid ${USER_GID} ${USERNAME}; \
    fi && \
    if ! getent passwd ${USER_UID} > /dev/null 2>&1; then \
        useradd --uid ${USER_UID} --gid ${USER_GID} -m ${USERNAME}; \
    fi && \
    chown -R ${USER_UID}:${USER_GID} /opt/vcpkg* /workspace && \
    chmod -R 777 /opt/vcpkg /opt/vcpkg-downloads /opt/vcpkg-cache /workspace

USER ${USER_UID}:${USER_GID}

# Verify everything is working
RUN gcc --version && \
    g++ --version && \
    clang++ --version && \
    cmake --version && \
    ninja --version && \
    vcpkg version

# Default command
CMD ["/bin/bash"]
