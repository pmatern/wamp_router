#!/usr/bin/env bash
# Build the C++23 build container image
# Usage: ./scripts/build.sh [--dev] [--no-cache]

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Script directory and project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Default values
DEV_MODE=false
NO_CACHE=""
VCPKG_VERSION="${VCPKG_VERSION:-2024.11.16}"
USER_UID="${USER_UID:-1000}"
USER_GID="${USER_GID:-1000}"

# Read version from .version file
VERSION=$(cat "${PROJECT_ROOT}/.version" | tr -d '[:space:]')

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --dev)
            DEV_MODE=true
            shift
            ;;
        --no-cache)
            NO_CACHE="--no-cache"
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --dev         Build development variant (Dockerfile.dev)"
            echo "  --no-cache    Build without using cache"
            echo "  -h, --help    Show this help message"
            echo ""
            echo "Environment variables:"
            echo "  VCPKG_VERSION  vcpkg version to use (default: 2024.11.16)"
            echo "  USER_UID       User UID for builder user (default: 1000)"
            echo "  USER_GID       User GID for builder user (default: 1000)"
            exit 0
            ;;
        *)
            echo -e "${RED}Error: Unknown option $1${NC}"
            exit 1
            ;;
    esac
done

# Determine image name and Dockerfile
if [ "$DEV_MODE" = true ]; then
    IMAGE_NAME="cpp23-builder-dev"
    DOCKERFILE="${PROJECT_ROOT}/Dockerfile.dev"
    if [ ! -f "$DOCKERFILE" ]; then
        echo -e "${RED}Error: Dockerfile.dev not found${NC}"
        echo "Development variant is not yet available. Use standard build."
        exit 1
    fi
else
    IMAGE_NAME="cpp23-builder"
    DOCKERFILE="${PROJECT_ROOT}/Dockerfile"
fi

# Check if Docker is available
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Error: docker command not found${NC}"
    echo "Please install Docker first."
    exit 1
fi

# Enable BuildKit for better caching and performance
export DOCKER_BUILDKIT=1

echo -e "${GREEN}Building ${IMAGE_NAME}:${VERSION}${NC}"
echo "  Dockerfile: ${DOCKERFILE}"
echo "  vcpkg version: ${VCPKG_VERSION}"
echo "  User UID:GID: ${USER_UID}:${USER_GID}"
echo "  No cache: ${NO_CACHE:-no}"
echo ""

# Build the image
docker build \
    ${NO_CACHE} \
    --build-arg VCPKG_VERSION="${VCPKG_VERSION}" \
    --build-arg USER_UID="${USER_UID}" \
    --build-arg USER_GID="${USER_GID}" \
    --tag "${IMAGE_NAME}:${VERSION}" \
    --tag "${IMAGE_NAME}:latest" \
    --file "${DOCKERFILE}" \
    "${PROJECT_ROOT}"

if [ $? -eq 0 ]; then
    echo ""
    echo -e "${GREEN}Successfully built ${IMAGE_NAME}:${VERSION}${NC}"
    echo ""
    echo "Tagged as:"
    echo "  - ${IMAGE_NAME}:${VERSION}"
    echo "  - ${IMAGE_NAME}:latest"
    echo ""
    echo "To test the image:"
    echo "  docker run --rm ${IMAGE_NAME}:latest clang++ --version"
    echo ""
    echo "To start using the container:"
    echo "  ./scripts/shell.sh"
else
    echo -e "${RED}Build failed${NC}"
    exit 1
fi
