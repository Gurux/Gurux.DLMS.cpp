project(GURUX.DLMS.cpp)

cmake_minimum_required(VERSION 3.9)

find_package (Threads REQUIRED)

option(BUILD_EXAMPLE "Build Examples" OFF)
option(BUILD_SHARED_LIBS "Build Shared Libs" OFF)

set(EXECUTABLE_OUTPUT_PATH ${CMAKE_SOURCE_DIR}/bin)
set(LIBRARY_OUTPUT_PATH ${CMAKE_SOURCE_DIR}/lib)

add_subdirectory(development)

if(BUILD_EXAMPLE)
  add_subdirectory(GuruxDLMSClientExample)
  add_subdirectory(GuruxDLMSPushExample)
  add_subdirectory(GuruxDLMSServerExample)
endif()
