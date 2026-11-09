cmake_minimum_required(VERSION 3.25)
project(WAMPRouter CXX)

# Standalone Asio, header only
add_compile_definitions(ASIO_STANDALONE)

# Set C++23 standard
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find packages installed by vcpkg
find_package(asio CONFIG REQUIRED)  # standalone Asio (std::error_code, no Boost)
find_package(spdlog CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)  # tests only: the independent CBOR oracle
find_package(Catch2 3 CONFIG REQUIRED)
find_package(toml11 CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)

# Create executable
add_executable(wamp_router main.cpp)

# Add include directory for header-only library
target_include_directories(wamp_router PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# Link libraries
target_link_libraries(wamp_router PRIVATE
    asio::asio
    spdlog::spdlog
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
    tests/test_realms.cpp
    tests/test_cbor.cpp
    tests/test_cpu_limits.cpp
    tests/test_router.cpp
    tests/test_logging.cpp
    tests/test_websocket.cpp
    tests/test_json.cpp
    tests/test_concepts.cpp
    tests/test_type_traits.cpp
)

# Add include directory for tests
target_include_directories(wamp_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# Link test libraries
target_link_libraries(wamp_tests PRIVATE
    asio::asio
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
    asio::asio
    spdlog::spdlog
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
    asio::asio
    spdlog::spdlog
    toml11::toml11
    OpenSSL::SSL
    OpenSSL::Crypto
)
target_compile_options(wamp_load PRIVATE -Wall -Wextra -Wpedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    target_compile_options(wamp_load PRIVATE -O3)
endif()


# Plain-TCP router for profiling with perf (not built by default)
#   cmake --build build-local-release --target wamp_profile_router
add_executable(wamp_profile_router EXCLUDE_FROM_ALL bench/profile_router.cpp)
target_include_directories(wamp_profile_router PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(wamp_profile_router PRIVATE
    asio::asio
    spdlog::spdlog
    toml11::toml11
    OpenSSL::SSL
    OpenSSL::Crypto
)
target_compile_options(wamp_profile_router PRIVATE -Wall -Wextra -Wpedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    target_compile_options(wamp_profile_router PRIVATE -O3)
endif()

find_package(Threads REQUIRED)

# Cross-thread handoff primitives (not built by default; run a Release build)
#   cmake --build build-local-release --target wamp_handoff_bench
add_executable(wamp_handoff_bench EXCLUDE_FROM_ALL bench/bench_handoff.cpp)
target_include_directories(wamp_handoff_bench PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(wamp_handoff_bench PRIVATE asio::asio Threads::Threads)
target_compile_options(wamp_handoff_bench PRIVATE -Wall -Wextra -Wpedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    target_compile_options(wamp_handoff_bench PRIVATE -O3)
endif()

# TLS 1.3 cost per connection and per message (not built by default; run a Release build)
#   cmake --build build-local-release --target wamp_tls_probe
add_executable(wamp_tls_probe EXCLUDE_FROM_ALL bench/tls_probe.cpp)
target_include_directories(wamp_tls_probe PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(wamp_tls_probe PRIVATE asio::asio OpenSSL::SSL OpenSSL::Crypto Threads::Threads)
target_compile_options(wamp_tls_probe PRIVATE -Wall -Wextra -Wpedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    target_compile_options(wamp_tls_probe PRIVATE -O3)
endif()
