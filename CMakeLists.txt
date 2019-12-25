cmake_minimum_required(VERSION 3.12.4)
project(llinst)

find_package(LLVM REQUIRED CONFIG)

add_definitions(${LLVM_DEFINITIONS})
include_directories(${LLVM_INCLUDE_DIRS})

include_directories(bpfinst-spec/include)

# Do not crash at Clang exit -- like in AFL llvm-mode
set(CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS} -z nodelete")

add_custom_command(
    OUTPUT ${CMAKE_BINARY_DIR}/noninstrumented.o
    COMMAND clang ARGS -ggdb3 -O3 -c ${CMAKE_SOURCE_DIR}/noninstrumented.c -o ${CMAKE_BINARY_DIR}/noninstrumented.o -fPIC
    DEPENDS ${CMAKE_SOURCE_DIR}/noninstrumented.c
)

add_custom_target(Runtime ALL DEPENDS ${CMAKE_BINARY_DIR}/noninstrumented.o)

add_subdirectory("LLInst")
