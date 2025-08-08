cmake_minimum_required(VERSION 3.16)
project(CybersecurityTool VERSION 1.0.0)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/include)

# Create a simple main executable
add_executable(CybersecurityTool src/main_simple.cpp)

# Create unit tests executable
add_executable(unit_tests tests/unit_tests_simple.cpp)

# Set output directories
set_target_properties(CybersecurityTool PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY_DEBUG ${CMAKE_BINARY_DIR}/bin/Debug
    RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_BINARY_DIR}/bin/Release
)

set_target_properties(unit_tests PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY_DEBUG ${CMAKE_BINARY_DIR}/bin/Debug
    RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_BINARY_DIR}/bin/Release
)

# Compiler-specific options
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_compile_options(CybersecurityTool PRIVATE -Wall -Wextra -O2)
    target_compile_options(unit_tests PRIVATE -Wall -Wextra -O2)
endif()
