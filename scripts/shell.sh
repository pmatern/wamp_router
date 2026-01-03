#!/usr/bin/env bash
# Start an interactive shell in the C++23 build container
# Usage: ./scripts/shell.sh [-p PORT]
#
# This script automatically mounts:
# - Current directory to /workspace
# - ~/.vcpkg-cache to /opt/vcpkg-cache (for binary caching)

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
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
            echo "Usage: $0 [-p PORT]"
            echo ""
            echo "Start an interactive shell in the C++23 build container."
            echo ""
            echo "Options:"
            echo "  -p, --publish PORT   Publish container port to host (e.g., -p 8080:8080)"
            echo "  -h, --help           Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0"
            echo "  $0 -p 8080:8080"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

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

echo -e "${GREEN}Starting interactive shell in ${IMAGE_NAME}${NC}"
echo "Workspace: ${WORKSPACE_DIR} -> /workspace"
echo "vcpkg cache: ${VCPKG_CACHE_DIR} -> /opt/vcpkg-cache"
echo ""
echo "Type 'exit' to leave the container."
echo ""

# Start interactive shell
docker run --rm -it \
    -v "${WORKSPACE_DIR}:/workspace" \
    -v "${VCPKG_CACHE_DIR}:/opt/vcpkg-cache" \
    -u "${CURRENT_UID}:${CURRENT_GID}" \
    -w /workspace \
    ${DOCKER_ARGS[@]+"${DOCKER_ARGS[@]}"} \
    "${IMAGE_NAME}" \
    /bin/bash
