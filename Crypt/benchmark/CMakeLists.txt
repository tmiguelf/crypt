cmake_minimum_required(VERSION 4.2.3)
project(crypt_lib_benchmark)
enable_language(CXX)

file(GLOB_RECURSE SOURCE_FILES CONFIGURE_DEPENDS 
	"./src/*.cpp"
)

add_executable(${PROJECT_NAME} ${SOURCE_FILES} ${RESOURCE_FILES})

target_link_libraries(${PROJECT_NAME} PRIVATE crypt_lib)
target_link_libraries(${PROJECT_NAME} PRIVATE benchmark benchmark_main)

quick_default_post_config()
