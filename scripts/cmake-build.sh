#!/usr/bin/env bash
# Execute CMake configure and build in the C++23 build container
# Usage: ./scripts/cmake-build.sh [OPTIONS]

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default values
BUILD_DIR="build"
BUILD_TYPE="Release"
TARGET=""
CLEAN_BUILD=false
CONFIGURE_ONLY=false
BUILD_ONLY=false
PARALLEL_JOBS=""

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --build-dir)
            BUILD_DIR="$2"
            shift 2
            ;;
        --build-type)
            BUILD_TYPE="$2"
            shift 2
            ;;
        --target)
            TARGET="$2"
            shift 2
            ;;
        --clean)
            CLEAN_BUILD=true
            shift
            ;;
        --configure-only)
            CONFIGURE_ONLY=true
            shift
            ;;
        --build-only)
            BUILD_ONLY=true
            shift
            ;;
        -j|--parallel)
            PARALLEL_JOBS="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Execute CMake configure and build in the container."
            echo ""
            echo "Options:"
            echo "  --build-dir DIR      Build directory (default: build)"
            echo "  --build-type TYPE    CMake build type (default: Release)"
            echo "  --target TARGET      Build specific target"
            echo "  --clean              Clean build directory before configure"
            echo "  --configure-only     Only run CMake configure step"
            echo "  --build-only         Only run build step (skip configure)"
            echo "  -j, --parallel N     Number of parallel build jobs"
            echo "  -h, --help           Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0"
            echo "  $0 --build-type Debug"
            echo "  $0 --target my_target"
            echo "  $0 --clean --build-type Release"
            exit 0
            ;;
        *)
            echo -e "${RED}Error: Unknown option $1${NC}"
            exit 1
            ;;
    esac
done

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Clean build directory if requested
if [ "$CLEAN_BUILD" = true ]; then
    echo -e "${YELLOW}Cleaning build directory: ${BUILD_DIR}${NC}"
    rm -rf "${BUILD_DIR}"
fi

# CMake configure step
if [ "$BUILD_ONLY" = false ]; then
    echo -e "${GREEN}Running CMake configure...${NC}"
    echo "  Build directory: ${BUILD_DIR}"
    echo "  Build type: ${BUILD_TYPE}"
    echo ""

    "${SCRIPT_DIR}/run.sh" cmake -B "${BUILD_DIR}" \
        -DCMAKE_TOOLCHAIN_FILE=/opt/vcpkg/scripts/buildsystems/vcpkg.cmake \
        -DCMAKE_C_COMPILER=clang-18 \
        -DCMAKE_CXX_COMPILER=clang++-18 \
        -DCMAKE_BUILD_TYPE="${BUILD_TYPE}" \
        -G Ninja

    if [ $? -ne 0 ]; then
        echo -e "${RED}CMake configure failed${NC}"
        exit 1
    fi

    echo -e "${GREEN}CMake configure completed successfully${NC}"
    echo ""
fi

# Build step
if [ "$CONFIGURE_ONLY" = false ]; then
    echo -e "${GREEN}Running build...${NC}"

    BUILD_ARGS=("cmake" "--build" "${BUILD_DIR}")

    if [ -n "${TARGET}" ]; then
        BUILD_ARGS+=("--target" "${TARGET}")
        echo "  Target: ${TARGET}"
    fi

    if [ -n "${PARALLEL_JOBS}" ]; then
        BUILD_ARGS+=("--parallel" "${PARALLEL_JOBS}")
        echo "  Parallel jobs: ${PARALLEL_JOBS}"
    fi

    echo ""

    "${SCRIPT_DIR}/run.sh" "${BUILD_ARGS[@]}"

    if [ $? -ne 0 ]; then
        echo -e "${RED}Build failed${NC}"
        exit 1
    fi

    echo ""
    echo -e "${GREEN}Build completed successfully${NC}"
fi

echo ""
echo "Build artifacts are in: ${BUILD_DIR}"
