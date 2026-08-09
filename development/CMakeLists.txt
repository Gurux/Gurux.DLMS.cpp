project(gurux_dlms_cpp)

cmake_minimum_required(VERSION 3.9)

file(GLOB sources ${PROJECT_SOURCE_DIR}/src/*.cpp)

add_library(gurux_dlms_cpp
  ${sources}
)

target_include_directories(gurux_dlms_cpp
  PUBLIC
    ${PROJECT_SOURCE_DIR}/include/
)

target_compile_options(gurux_dlms_cpp
  PUBLIC
    -Wall -fPIC
)

install(TARGETS gurux_dlms_cpp
  DESTINATION ${CMAKE_INSTALL_PREFIX}/lib
)

install(DIRECTORY "${PROJECT_SOURCE_DIR}/include/"
  DESTINATION ${CMAKE_INSTALL_PREFIX}/include
  FILES_MATCHING PATTERN "*.*h"
)