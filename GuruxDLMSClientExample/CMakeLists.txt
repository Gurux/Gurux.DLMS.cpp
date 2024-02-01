project(gurux_dlms_cpp_client_example)

cmake_minimum_required(VERSION 3.9)

file(GLOB sources src/*.cpp)

add_executable(gurux.dlms.client.bin
  ${sources}
)

target_include_directories(gurux.dlms.client.bin
  PUBLIC
    include
)

target_compile_options(gurux.dlms.client.bin
  PUBLIC
    -Wall -fPIC
)

target_link_libraries(gurux.dlms.client.bin
  gurux_dlms_cpp
)
