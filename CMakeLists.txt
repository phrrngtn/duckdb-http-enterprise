cmake_minimum_required(VERSION 3.14...3.29)
option(DUCKDB_WASM_EXTENSION "Whether compiling for Wasm target" OFF)

###
# Configuration
###
if(NOT DEFINED EXTENSION_NAME)
    message(FATAL_ERROR "DuckDB extension name is required")
endif()
if (DEFINED TARGET_DUCKDB_VERSION_MAJOR)
    add_definitions(-DDUCKDB_EXTENSION_API_VERSION_MAJOR=${TARGET_DUCKDB_VERSION_MAJOR})
endif()
if (DEFINED TARGET_DUCKDB_VERSION_MINOR)
    add_definitions(-DDUCKDB_EXTENSION_API_VERSION_MINOR=${TARGET_DUCKDB_VERSION_MINOR})
endif()
if (DEFINED TARGET_DUCKDB_VERSION_PATCH)
    add_definitions(-DDUCKDB_EXTENSION_API_VERSION_PATCH=${TARGET_DUCKDB_VERSION_PATCH})
endif()

add_definitions(-DDUCKDB_EXTENSION_NAME=${EXTENSION_NAME})

if (DEFINED DUCKDB_EXTENSION_API_VERSION_UNSTABLE)
    add_definitions(-DDUCKDB_EXTENSION_API_VERSION_UNSTABLE=${DUCKDB_EXTENSION_API_VERSION_UNSTABLE})
endif()

###
# Build
###
project(${EXTENSION_NAME} LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# All code (including static deps like cpr/libcurl) must be compiled with -fPIC
# since the extension is a shared library.
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

###
# Dependencies
###
include(FetchContent)

# nlohmann/json — header-only JSON library
FetchContent_Declare(
    nlohmann_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG        v3.11.3
    GIT_SHALLOW    TRUE
)
set(JSON_BuildTests OFF CACHE INTERNAL "")
FetchContent_MakeAvailable(nlohmann_json)

# cpr — C++ Requests: Curl for People
FetchContent_Declare(
    cpr
    GIT_REPOSITORY https://github.com/libcpr/cpr.git
    GIT_TAG        1.11.2
    GIT_SHALLOW    TRUE
)
set(CPR_BUILD_TESTS OFF CACHE INTERNAL "")
set(BUILD_SHARED_LIBS OFF CACHE INTERNAL "")
FetchContent_MakeAvailable(cpr)

###
# Embed SQL macros as C++ string constants
###
file(GLOB SQL_FILES ${CMAKE_SOURCE_DIR}/sql/*.sql)
set(SQL_RESOURCES_HEADER ${CMAKE_BINARY_DIR}/sql_resources.hpp)
find_package(Python3 REQUIRED COMPONENTS Interpreter)
add_custom_command(
    OUTPUT ${SQL_RESOURCES_HEADER}
    COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_SOURCE_DIR}/cmake/embed_sql.py
        ${CMAKE_SOURCE_DIR}/sql
        ${SQL_RESOURCES_HEADER}
    DEPENDS ${SQL_FILES} ${CMAKE_SOURCE_DIR}/cmake/embed_sql.py
    COMMENT "Embedding SQL macros into sql_resources.hpp"
)

# Extension sources
set(EXTENSION_SOURCES
        src/http_client_extension.cpp
        src/http_functions.cpp
        src/negotiate_auth.cpp
        ${SQL_RESOURCES_HEADER}
)

if (DUCKDB_WASM_EXTENSION)
	add_library(${EXTENSION_NAME} STATIC ${EXTENSION_SOURCES})
else()
	add_library(${EXTENSION_NAME} SHARED ${EXTENSION_SOURCES})
	if(WIN32 AND MINGW)
		set_target_properties(${EXTENSION_NAME} PROPERTIES PREFIX "")
	endif()
endif()

# Hide symbols
set(CMAKE_CXX_VISIBILITY_PRESET hidden)
set(CMAKE_C_VISIBILITY_PRESET hidden)
set(VISIBILITY_INLINES_HIDDEN ON)
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -s")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -s")

# Include own headers and generated headers
target_include_directories(${EXTENSION_NAME} PRIVATE src/include ${CMAKE_BINARY_DIR})

# Include DuckDB C API headers
target_include_directories(${EXTENSION_NAME} PRIVATE duckdb_capi)

# On macOS with Homebrew, ensure linker can find Homebrew libraries (e.g. libidn2)
if(APPLE)
    execute_process(
        COMMAND brew --prefix
        OUTPUT_VARIABLE HOMEBREW_PREFIX
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
    )
    if(HOMEBREW_PREFIX)
        target_link_directories(${EXTENSION_NAME} PRIVATE ${HOMEBREW_PREFIX}/lib)
    endif()
endif()

# Link dependencies
target_link_libraries(${EXTENSION_NAME} PRIVATE nlohmann_json::nlohmann_json cpr::cpr)

# Link SSPI on Windows
if(WIN32)
    target_link_libraries(${EXTENSION_NAME} PRIVATE secur32)
endif()
