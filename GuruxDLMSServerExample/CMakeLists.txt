project(gurux_dlms_cpp_server_example)

cmake_minimum_required(VERSION 3.9)

file(GLOB sources src/*.cpp)

add_executable(gurux.dlms.server.bin
  ${sources}
)

target_include_directories(gurux.dlms.server.bin
  PUBLIC
    include
)

target_compile_options(gurux.dlms.server.bin
  PUBLIC
    -Wall -fPIC
)

target_link_libraries(gurux.dlms.server.bin
  gurux_dlms_cpp
  Threads::Threads
)