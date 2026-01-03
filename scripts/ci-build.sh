#!/usr/bin/env bash
# CI/CD optimized build script for the C++23 build container
# Usage: ./scripts/ci-build.sh [OPTIONS]
#
# This script is optimized for CI/CD environments with:
# - Non-interactive mode
# - Proper exit codes
# - Build output capture
# - Test execution support

set -euo pipefail

# Colors for output (disabled in CI if NO_COLOR is set)
if [ -z "${NO_COLOR:-}" ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    NC=''
fi

# Default values
BUILD_DIR="${BUILD_DIR:-build}"
BUILD_TYPE="${BUILD_TYPE:-Release}"
RUN_TESTS="${RUN_TESTS:-true}"
PARALLEL_JOBS="${PARALLEL_JOBS:-}"

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
        --no-tests)
            RUN_TESTS=false
            shift
            ;;
        -j|--parallel)
            PARALLEL_JOBS="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "CI/CD optimized build script."
            echo ""
            echo "Options:"
            echo "  --build-dir DIR      Build directory (default: build, env: BUILD_DIR)"
            echo "  --build-type TYPE    CMake build type (default: Release, env: BUILD_TYPE)"
            echo "  --no-tests           Skip running tests (default: run tests, env: RUN_TESTS=false)"
            echo "  -j, --parallel N     Number of parallel jobs (env: PARALLEL_JOBS)"
            echo "  -h, --help           Show this help message"
            echo ""
            echo "Environment variables:"
            echo "  BUILD_DIR            Build directory"
            echo "  BUILD_TYPE           CMake build type"
            echo "  RUN_TESTS            Set to 'false' to skip tests"
            echo "  PARALLEL_JOBS        Number of parallel build jobs"
            echo "  NO_COLOR             Disable colored output"
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

# Log function
log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $*"
}

# Start CI build
log_info "Starting CI build"
log_info "Build directory: ${BUILD_DIR}"
log_info "Build type: ${BUILD_TYPE}"
log_info "Run tests: ${RUN_TESTS}"
echo ""

# Step 1: CMake Configure
log_info "Step 1/3: Running CMake configure..."
if ! "${SCRIPT_DIR}/run.sh" cmake -B "${BUILD_DIR}" \
    -DCMAKE_TOOLCHAIN_FILE=/opt/vcpkg/scripts/buildsystems/vcpkg.cmake \
    -DCMAKE_C_COMPILER=clang-18 \
    -DCMAKE_CXX_COMPILER=clang++-18 \
    -DCMAKE_BUILD_TYPE="${BUILD_TYPE}" \
    -G Ninja; then
    log_error "CMake configure failed"
    exit 1
fi
log_success "CMake configure completed"
echo ""

# Step 2: Build
log_info "Step 2/3: Running build..."
BUILD_ARGS=("cmake" "--build" "${BUILD_DIR}")

if [ -n "${PARALLEL_JOBS}" ]; then
    BUILD_ARGS+=("--parallel" "${PARALLEL_JOBS}")
    log_info "Using ${PARALLEL_JOBS} parallel jobs"
fi

if ! "${SCRIPT_DIR}/run.sh" "${BUILD_ARGS[@]}"; then
    log_error "Build failed"
    exit 1
fi
log_success "Build completed"
echo ""

# Step 3: Run tests (if enabled)
if [ "$RUN_TESTS" = true ]; then
    log_info "Step 3/3: Running tests..."

    # Check if CTest is available in the build
    if [ -f "${BUILD_DIR}/CTestTestfile.cmake" ]; then
        if ! "${SCRIPT_DIR}/run.sh" ctest --test-dir "${BUILD_DIR}" --output-on-failure; then
            log_error "Tests failed"
            exit 1
        fi
        log_success "All tests passed"
    else
        log_warning "No tests found (CTestTestfile.cmake not present)"
    fi
else
    log_info "Step 3/3: Skipping tests (disabled)"
fi

echo ""
log_success "CI build completed successfully"
log_info "Build artifacts are in: ${BUILD_DIR}"

exit 0
