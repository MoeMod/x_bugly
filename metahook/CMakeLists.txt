add_subdirectory(Detours)
add_library(metahook STATIC metahook.cpp)
target_include_directories(metahook PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(metahook PRIVATE Detours)