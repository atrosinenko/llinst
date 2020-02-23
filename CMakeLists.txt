cmake_minimum_required(VERSION 3.12.4)
project(llinst)

find_package(LLVM REQUIRED CONFIG)

add_definitions(${LLVM_DEFINITIONS})
include_directories(${LLVM_INCLUDE_DIRS})

include_directories(bpfinst-spec/include)

# Do not crash at Clang exit -- like in AFL llvm-mode
set(CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS} -z nodelete")

add_subdirectory("LLInst")
