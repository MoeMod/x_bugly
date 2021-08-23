cmake_minimum_required(VERSION 3.12)
project(x_bugly)

set(CMAKE_CXX_STANDARD 20)

if(MSVC)
	# force xp build
	add_definitions(-D_USING_V110_SDK71_)

	# MultiByte charset
	add_compile_options(/utf-8)

	# static CRT
	set(CompilerFlags
		CMAKE_CXX_FLAGS
		CMAKE_CXX_FLAGS_DEBUG
		CMAKE_CXX_FLAGS_RELEASE
		CMAKE_CXX_FLAGS_MINSIZEREL
		CMAKE_CXX_FLAGS_RELWITHDEBINFO
		CMAKE_C_FLAGS
		CMAKE_C_FLAGS_DEBUG
		CMAKE_C_FLAGS_RELEASE
		CMAKE_C_FLAGS_MINSIZEREL
		CMAKE_C_FLAGS_RELWITHDEBINFO
		)
	foreach(CompilerFlag ${CompilerFlags})
		string(REPLACE "/MD" "/MT" ${CompilerFlag} "${${CompilerFlag}}")
	endforeach()
endif()

add_library(amxx_module_sdk INTERFACE)
target_sources(amxx_module_sdk INTERFACE
	${CMAKE_SOURCE_DIR}/sdk/amxxmodule.cpp
	${CMAKE_SOURCE_DIR}/sdk/amxxmodule.h
)
target_include_directories(amxx_module_sdk INTERFACE
	${CMAKE_SOURCE_DIR}/sdk/
)
target_compile_definitions(amxx_module_sdk INTERFACE
	-DHAVE_STDINT_H=1
)

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