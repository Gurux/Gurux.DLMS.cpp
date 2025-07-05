cmake_minimum_required(VERSION 3.15)
project(GuruxDLMS LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Источники библиотеки
file(GLOB_RECURSE GXDLMS_SOURCES development/src/*.cpp)
file(GLOB_RECURSE GXDLMS_HEADERS development/include/*.h)

add_library(gurux_dlms STATIC ${GXDLMS_SOURCES})
target_include_directories(gurux_dlms PUBLIC development/include)

# Client
file(GLOB_RECURSE GXDLMS_SOURCES GuruxDLMSClientExample/src/*.cpp)
add_executable(gurux_client ${GXDLMS_SOURCES})
target_link_libraries(gurux_client PRIVATE gurux_dlms)

# Listener
file(GLOB_RECURSE GXDLMS_SOURCES GuruxDLMSMeterListener/src/*.cpp)
add_executable(gurux_listener ${GXDLMS_SOURCES})
target_link_libraries(gurux_listener PRIVATE gurux_dlms)

# Listener
file(GLOB_RECURSE GXDLMS_SOURCES GuruxDLMSPushExample/src/*.cpp)
add_executable(gurux_push ${GXDLMS_SOURCES})
target_link_libraries(gurux_push PRIVATE gurux_dlms)

# Listener
file(GLOB_RECURSE GXDLMS_SOURCES GuruxDLMSServerExample/src/*.cpp)
add_executable(gurux_server ${GXDLMS_SOURCES})
target_link_libraries(gurux_server PRIVATE gurux_dlms)

enable_testing()
