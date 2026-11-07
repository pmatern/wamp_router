cmake_minimum_required(VERSION 3.25)
project(WAMPRouter CXX)

# Set C++23 standard
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find packages installed by vcpkg
find_package(Boost REQUIRED COMPONENTS system)
find_package(fmt CONFIG REQUIRED)
find_package(spdlog CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(Catch2 3 CONFIG REQUIRED)
find_package(toml11 CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)

# Create executable
add_executable(wamp_router main.cpp)

# Add include directory for header-only library
target_include_directories(wamp_router PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# Link libraries
target_link_libraries(wamp_router PRIVATE
    Boost::system
    Boost::boost  # Header-only Boost.Asio
    fmt::fmt
    spdlog::spdlog
    nlohmann_json::nlohmann_json
    toml11::toml11
    OpenSSL::SSL
    OpenSSL::Crypto
)

# Compiler flags
target_compile_options(wamp_router PRIVATE
    -Wall
    -Wextra
    -Wpedantic
)

# Optional: Set optimization flags for Release builds
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    target_compile_options(wamp_router PRIVATE -O3)
endif()

# Enable testing
enable_testing()

# Create test executable
add_executable(wamp_tests
    tests/test_main.cpp
    tests/test_wamp_id.cpp
    tests/test_raw_socket.cpp
    tests/test_wamp_serializer.cpp
    tests/test_subscription_manager.cpp
    tests/test_wamp_session.cpp
    tests/test_procedure_handler.cpp
    tests/test_integration.cpp
    tests/test_config.cpp
    tests/test_wamp_client.cpp
    tests/test_protocol_gaps.cpp
    tests/test_event_queue.cpp
    tests/test_crypto_utils.cpp
    tests/test_authorization.cpp
)

# Add include directory for tests
target_include_directories(wamp_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# Link test libraries
target_link_libraries(wamp_tests PRIVATE
    Boost::system
    Boost::boost
    fmt::fmt
    spdlog::spdlog
    nlohmann_json::nlohmann_json
    Catch2::Catch2WithMain
    toml11::toml11
    OpenSSL::SSL
    OpenSSL::Crypto
)

# Compiler flags for tests
target_compile_options(wamp_tests PRIVATE
    -Wall
    -Wextra
    -Wpedantic
)

# Register tests with CTest
include(CTest)
include(Catch)
catch_discover_tests(wamp_tests)

# Micro-benchmarks (not built by default; run a Release build)
#   cmake --build build-local-release --target wamp_bench
add_executable(wamp_bench EXCLUDE_FROM_ALL bench/bench_micro.cpp)
target_include_directories(wamp_bench PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(wamp_bench PRIVATE
    Boost::system
    Boost::boost
    fmt::fmt
    spdlog::spdlog
    nlohmann_json::nlohmann_json
    Catch2::Catch2WithMain
    toml11::toml11
    OpenSSL::SSL
    OpenSSL::Crypto
)
target_compile_options(wamp_bench PRIVATE -Wall -Wextra -Wpedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    target_compile_options(wamp_bench PRIVATE -O3)
endif()

# End-to-end load test (not built by default; run a Release build)
#   cmake --build build-local-release --target wamp_load
add_executable(wamp_load EXCLUDE_FROM_ALL bench/load_test.cpp)
target_include_directories(wamp_load PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(wamp_load PRIVATE
    Boost::system
    Boost::boost
    fmt::fmt
    spdlog::spdlog
    nlohmann_json::nlohmann_json
    toml11::toml11
    OpenSSL::SSL
    OpenSSL::Crypto
)
target_compile_options(wamp_load PRIVATE -Wall -Wextra -Wpedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    target_compile_options(wamp_load PRIVATE -O3)
endif()

