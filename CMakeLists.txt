cmake_minimum_required(VERSION 3.10)
project(RSAProject)

# Compiler settings
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED True)

# Directories
set(SRC_DIR "${CMAKE_SOURCE_DIR}/src")
set(INCLUDE_DIR "${CMAKE_SOURCE_DIR}/include")

# Find all .c source files automatically
file(GLOB SRC_FILES "${SRC_DIR}/*.c")

# Create executable
add_executable(rsa ${SRC_FILES})

# Runtime files
target_compile_definitions(rsa PRIVATE DATA_DIR="${CMAKE_SOURCE_DIR}/data")

# Include directories
target_include_directories(rsa PRIVATE ${INCLUDE_DIR})

# Link external libraries
target_link_libraries(rsa gmp ssl crypto)

# Output executable in the build directory
set_target_properties(rsa PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin")