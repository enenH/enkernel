cmake_minimum_required(VERSION 3.22)
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    project(enkernel VERSION 0.1.0 LANGUAGES CXX)
endif()

if(NOT ANDROID OR NOT CMAKE_ANDROID_ARCH_ABI STREQUAL "arm64-v8a")
    message(FATAL_ERROR "Use the Android NDK toolchain with -DANDROID_ABI=arm64-v8a")
endif()
if(ANDROID_NATIVE_API_LEVEL LESS 26)
    message(FATAL_ERROR "Use -DANDROID_PLATFORM=android-26 or newer")
endif()

option(ENKERNEL_BUILD_TOOLS "Build the dfm_loader command-line tool" ON)
option(ENKERNEL_BUILD_EXAMPLE "Build the SDK calling example" ON)

# The kernel ABI is the only source of truth, including in installed SDKs.
configure_file(../abi.h include/dfm/abi.h COPYONLY)

add_library(enkernel_sdk STATIC src/driver.cpp src/loader.cpp)
add_library(enkernel::sdk ALIAS enkernel_sdk)
set_target_properties(enkernel_sdk PROPERTIES
    EXPORT_NAME sdk
    POSITION_INDEPENDENT_CODE ON
)
target_compile_features(enkernel_sdk PUBLIC cxx_std_20)
target_compile_options(enkernel_sdk PRIVATE -Wall -Wextra -Wpedantic)
target_include_directories(enkernel_sdk PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
    $<INSTALL_INTERFACE:include>
)
target_link_libraries(enkernel_sdk PUBLIC log)
# Propagate ELF alignment to tools and external consumers for 16 KiB devices.
target_link_options(enkernel_sdk INTERFACE "LINKER:-z,max-page-size=16384")

if(ENKERNEL_BUILD_TOOLS)
    add_executable(dfm_loader tools/dfm_loader.cpp)
    target_link_libraries(dfm_loader PRIVATE enkernel::sdk)
    target_compile_options(dfm_loader PRIVATE -Wall -Wextra -Wpedantic)
    install(TARGETS dfm_loader RUNTIME DESTINATION bin)
endif()
if(ENKERNEL_BUILD_EXAMPLE)
    add_executable(dfm_example examples/basic.cpp)
    target_link_libraries(dfm_example PRIVATE enkernel::sdk)
    target_compile_options(dfm_example PRIVATE -Wall -Wextra -Wpedantic)
    install(TARGETS dfm_example RUNTIME DESTINATION bin)
endif()

include(CMakePackageConfigHelpers)
configure_package_config_file(cmake/enkernelConfig.cmake.in
    "${CMAKE_CURRENT_BINARY_DIR}/enkernelConfig.cmake"
    INSTALL_DESTINATION lib/cmake/enkernel
)
write_basic_package_version_file("${CMAKE_CURRENT_BINARY_DIR}/enkernelConfigVersion.cmake"
    VERSION 0.1.0 COMPATIBILITY SameMajorVersion
)
install(TARGETS enkernel_sdk EXPORT enkernelTargets ARCHIVE DESTINATION lib)
install(EXPORT enkernelTargets NAMESPACE enkernel:: DESTINATION lib/cmake/enkernel)
install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/enkernelConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/enkernelConfigVersion.cmake"
    DESTINATION lib/cmake/enkernel
)
install(DIRECTORY include/dfm DESTINATION include)
install(FILES ../abi.h DESTINATION include/dfm)
install(FILES examples/basic.cpp examples/CMakeLists.txt DESTINATION examples)
