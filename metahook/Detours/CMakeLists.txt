include(ExternalProject)
enable_language(C CXX ASM_MASM)

ExternalProject_Add(DetoursSrc
	GIT_REPOSITORY https://github.com/microsoft/Detours.git
	GIT_TAG master
	GIT_SHALLOW YES
	CONFIGURE_COMMAND ""
	BUILD_COMMAND ""
	INSTALL_COMMAND ""
	TEST_COMMAND ""
	BINARY_DIR ${CMAKE_BINARY_DIR}/Detours-Build/detours
)
ExternalProject_Get_Property(DetoursSrc SOURCE_DIR)
set(DETOURS_SOURCES
	${CMAKE_BINARY_DIR}/Detours-Build/detours/detours.cpp
	${CMAKE_BINARY_DIR}/Detours-Build/detours/modules.cpp
	${CMAKE_BINARY_DIR}/Detours-Build/detours/disasm.cpp
	${CMAKE_BINARY_DIR}/Detours-Build/detours/image.cpp
	${CMAKE_BINARY_DIR}/Detours-Build/detours/creatwth.cpp
	${CMAKE_BINARY_DIR}/Detours-Build/detours/disolx86.cpp
	${CMAKE_BINARY_DIR}/Detours-Build/detours/disolx64.cpp
	${CMAKE_BINARY_DIR}/Detours-Build/detours/disolia64.cpp
	${CMAKE_BINARY_DIR}/Detours-Build/detours/disolarm.cpp
	${CMAKE_BINARY_DIR}/Detours-Build/detours/disolarm64.cpp)
add_custom_command(OUTPUT ${DETOURS_SOURCES}
	               COMMAND ${CMAKE_COMMAND} -E copy_directory ${SOURCE_DIR}/src/ ${CMAKE_BINARY_DIR}/Detours-Build/detours
				   DEPENDS DetoursSrc)
add_library(Detours STATIC ${DETOURS_SOURCES})
target_include_directories(Detours PUBLIC ${CMAKE_BINARY_DIR}/Detours-Build/)
add_dependencies(Detours DetoursSrc)