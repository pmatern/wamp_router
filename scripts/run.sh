#!/usr/bin/env bash
# Run a command in the C++23 build container
# Usage: ./scripts/run.sh [command]
#
# This script automatically mounts:
# - Current directory to /workspace
# - ~/.vcpkg-cache to /opt/vcpkg-cache (for binary caching)
#
# Examples:
#   ./scripts/run.sh clang++ --version
#   ./scripts/run.sh cmake -B build -DCMAKE_TOOLCHAIN_FILE=/opt/vcpkg/scripts/buildsystems/vcpkg.cmake

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Default image name
IMAGE_NAME="${CPP23_BUILDER_IMAGE:-cpp23-builder:latest}"

# Check if Docker is available
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Error: docker command not found${NC}"
    echo "Please install Docker first."
    exit 1
fi

# Check if image exists
if ! docker image inspect "${IMAGE_NAME}" &> /dev/null; then
    echo -e "${RED}Error: Docker image ${IMAGE_NAME} not found${NC}"
    echo "Please build the image first:"
    echo "  ./scripts/build.sh"
    exit 1
fi

# Get current user UID and GID
CURRENT_UID=$(id -u)
CURRENT_GID=$(id -g)

# Create vcpkg cache directory if it doesn't exist
VCPKG_CACHE_DIR="${HOME}/.vcpkg-cache"
mkdir -p "${VCPKG_CACHE_DIR}"

# Get absolute path of current directory
WORKSPACE_DIR="$(pwd)"

# Parse options for port publishing
DOCKER_ARGS=()
while [[ $# -gt 0 ]]; do
    case $1 in
        -p|--publish)
            DOCKER_ARGS+=("-p" "$2")
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [-p PORT] [command]"
            echo ""
            echo "Run a command in the C++23 build container."
            echo ""
            echo "Options:"
            echo "  -p, --publish PORT   Publish container port to host (e.g., -p 8080:8080)"
            echo "  -h, --help           Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0 clang++ --version"
            echo "  $0 cmake -B build -G Ninja"
            echo "  $0 vcpkg search boost"
            echo "  $0 -p 8080:8080 ./build/http_server"
            echo ""
            echo "Environment variables:"
            echo "  CPP23_BUILDER_IMAGE  Docker image to use (default: cpp23-builder:latest)"
            exit 0
            ;;
        *)
            break
            ;;
    esac
done

# If no command provided, show help
if [ $# -eq 0 ]; then
    echo "Usage: $0 [-p PORT] [command]"
    echo "Run '$0 --help' for more information."
    exit 1
fi

# Run the command in the container
docker run --rm \
    -v "${WORKSPACE_DIR}:/workspace" \
    -v "${VCPKG_CACHE_DIR}:/opt/vcpkg-cache" \
    -u "${CURRENT_UID}:${CURRENT_GID}" \
    -w /workspace \
    ${DOCKER_ARGS[@]+"${DOCKER_ARGS[@]}"} \
    "${IMAGE_NAME}" \
    "$@"
