project(gurux_dlms_cpp_push_example)

cmake_minimum_required(VERSION 3.9)

file(GLOB sources src/*.cpp)

add_executable(gurux.dlms.push.bin
  ${sources}
)

target_include_directories(gurux.dlms.push.bin
  PUBLIC
    include
)

target_compile_options(gurux.dlms.push.bin
  PUBLIC
    -Wall -fPIC
)

target_link_libraries(gurux.dlms.push.bin
  gurux_dlms_cpp
  Threads::Threads
)
