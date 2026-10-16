cmake_minimum_required(VERSION 4.2.3)
project(crypt_builld)

set(INFO_CONFIG "${CMAKE_SYSTEM_NAME}_${CMAKE_CXX_COMPILER_ID}_${CMAKE_SYSTEM_PROCESSOR}_${CMAKE_BUILD_TYPE}")
set(CMAKE_PDB_OUTPUT_DIRECTORY "${PROJECT_SOURCE_DIR}/DebugData/${INFO_CONFIG}")
set(CMAKE_INSTALL_PREFIX "${PROJECT_SOURCE_DIR}/Runtime")

include("${CMAKE_CURRENT_SOURCE_DIR}/submodules/quick_cmake/quick.cmake")
quick_add_collection_presets()

add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/submodules/utilities/CoreLib")
add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/Crypt")

#Tests
set(INSTALL_GTEST False)
add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/submodules/googletest/")

set(BENCHMARK_ENABLE_EXCEPTIONS False)
#set(BENCHMARK_ENABLE_LTO True)
set(BENCHMARK_ENABLE_TESTING False)
set(BENCHMARK_ENABLE_GTEST_TESTS False)
set(BENCHMARK_ENABLE_INSTALL False)
set(BENCHMARK_INSTALL_DOCS False)
set(BENCHMARK_INSTALL_TOOLS False)
add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/submodules/benchmark")

add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/submodules/SCEF/SCEF")

add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/Crypt/test")
add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/Crypt/benchmark")

install(TARGETS crypt_lib_test DESTINATION "${INFO_CONFIG}")