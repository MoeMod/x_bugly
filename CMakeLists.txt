cmake_minimum_required(VERSION 3.12)
project(x_bugly)

set(CMAKE_CXX_STANDARD 20)

add_subdirectory(amxx_module_sdk)
add_subdirectory(metahook)

add_library(x_bugly SHARED
	${CMAKE_SOURCE_DIR}/main.cpp
	${CMAKE_SOURCE_DIR}/moduleconfig.h
)
target_include_directories(x_bugly PUBLIC
	${CMAKE_SOURCE_DIR}/
)

set_target_properties(x_bugly PROPERTIES OUTPUT_NAME x_bugly_amxx)
target_link_libraries(x_bugly PUBLIC metahook)
target_link_libraries(x_bugly PUBLIC amxx_module_sdk)