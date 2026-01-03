#!/usr/bin/env bash
# Debug an application in the C++23 build container
# Usage: ./scripts/debug.sh [-p PORT] <executable> [args]
#
# This script starts gdbserver in the container for remote debugging

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default image name
IMAGE_NAME="${CPP23_BUILDER_IMAGE:-cpp23-builder:latest}"

# Parse options for port publishing
DOCKER_ARGS=()
while [[ $# -gt 0 ]]; do
    case $1 in
        -p|--publish)
            DOCKER_ARGS+=("-p" "$2")
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [-p PORT] <executable> [args]"
            echo ""
            echo "Debug an application in the container using gdbserver."
            echo ""
            echo "Options:"
            echo "  -p, --publish PORT   Publish container port to host (e.g., -p 8080:8080)"
            echo "  -h, --help           Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0 ./build/http_server"
            echo "  $0 -p 8080:8080 ./build/http_server"
            echo ""
            echo "After starting, connect your IDE debugger to localhost:2345"
            exit 0
            ;;
        *)
            break
            ;;
    esac
done

# Check if Docker is available
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Error: docker command not found${NC}"
    exit 1
fi

# Check if image exists
if ! docker image inspect "${IMAGE_NAME}" &> /dev/null; then
    echo -e "${RED}Error: Docker image ${IMAGE_NAME} not found${NC}"
    echo "Please build the image first: ./scripts/build.sh"
    exit 1
fi

# Check if executable provided
if [ $# -eq 0 ]; then
    echo "Usage: $0 [-p PORT] <executable> [args]"
    echo "Run '$0 --help' for more information."
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

# Add gdbserver port (2345 is standard)
DOCKER_ARGS+=("-p" "2345:2345")

echo -e "${GREEN}Starting gdbserver in container...${NC}"
echo "Executable: $1"
echo "Arguments: ${@:2}"
echo ""
echo -e "${YELLOW}Connect your IDE debugger to: localhost:2345${NC}"
echo ""
echo "CLion: Run → Edit Configurations → + → Remote Debug"
echo "  - 'target remote' args: localhost:2345"
echo "  - Path mappings: /workspace -> $WORKSPACE_DIR"
echo ""

# Run gdbserver in the container
docker run --rm -it \
    -v "${WORKSPACE_DIR}:/workspace" \
    -v "${VCPKG_CACHE_DIR}:/opt/vcpkg-cache" \
    -u "${CURRENT_UID}:${CURRENT_GID}" \
    -w /workspace \
    ${DOCKER_ARGS[@]+"${DOCKER_ARGS[@]}"} \
    "${IMAGE_NAME}" \
    gdbserver :2345 "$@"
