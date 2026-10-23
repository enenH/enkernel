cmake_minimum_required(VERSION 3.22)
project(enkernel_sdk_example LANGUAGES CXX)

# Configure with the NDK toolchain and
# -Denkernel_DIR=/path/to/installed/sdk/lib/cmake/enkernel.
find_package(enkernel CONFIG REQUIRED)
add_executable(dfm_example basic.cpp)
target_link_libraries(dfm_example PRIVATE enkernel::sdk)
