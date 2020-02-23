add_library(noninstrumented OBJECT noninstrumented.c)
set_property(TARGET noninstrumented PROPERTY POSITION_INDEPENDENT_CODE ON)

add_custom_command(
    OUTPUT ${CMAKE_BINARY_DIR}/LLInst/noninstrumented.o
    COMMAND cp $<TARGET_OBJECTS:noninstrumented> ${CMAKE_BINARY_DIR}/LLInst/noninstrumented.o
    DEPENDS $<TARGET_OBJECTS:noninstrumented>)
add_custom_target(LLInstRuntime DEPENDS ${CMAKE_BINARY_DIR}/LLInst/noninstrumented.o)

add_library(LLInst MODULE Pass.cpp BpfLoader.cpp)
add_dependencies(LLInst LLInstRuntime)
