cmake_minimum_required(VERSION 3.25)
project(ar-tools VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# --- Dependencies -----------------------------------------------------------
find_package(OpenSSL REQUIRED)
find_package(GTest REQUIRED)

# rapidjson is a header-only library. Prefer a system package; fall back to
# fetching a pinned release if none is installed.
find_package(RapidJSON QUIET)
if(NOT RapidJSON_FOUND)
  include(FetchContent)
  FetchContent_Declare(
    rapidjson
    GIT_REPOSITORY https://github.com/Tencent/rapidjson.git
    GIT_TAG        v1.1.0
    GIT_SHALLOW    TRUE)
  # Only the header-only library is needed; skip rapidjson's own tests,
  # examples and docs (which fail to build under newer compilers).
  set(RAPIDJSON_BUILD_TESTS OFF CACHE BOOL "" FORCE)
  set(RAPIDJSON_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
  set(RAPIDJSON_BUILD_DOC OFF CACHE BOOL "" FORCE)
  FetchContent_MakeAvailable(rapidjson)
  # RapidJSON's CMakeLists uses a global include_directories() rather than a
  # target_include_directories(), so the include path is not propagated to
  # consumers. Add it explicitly.
  set(RAPIDJSON_INCLUDE_DIR ${rapidjson_SOURCE_DIR}/include)
else()
  set(RAPIDJSON_INCLUDE_DIR ${RapidJSON_INCLUDE_DIRS})
endif()

# --- Library -----------------------------------------------------------------
set(ARTOOLS_SOURCES
    libartools/src/wallet.cpp
    libartools/src/crypto/base64.cpp
    libartools/src/crypto/base64url.cpp
    libartools/src/crypto/bip39.cpp
    libartools/src/crypto/jwk.cpp
    libartools/src/crypto/pem.cpp
    libartools/src/crypto/sha256.cpp
    libartools/src/crypto/sha384.cpp
    libartools/src/transport/TLSClient.cpp
    libartools/src/protocol/GetBalance.cpp
    libartools/src/protocol/GetTurboBalance.cpp
    libartools/src/protocol/GetTxAnchor.cpp
    libartools/src/protocol/GetPrice.cpp
    libartools/src/protocol/Transaction.cpp)

add_library(artools SHARED ${ARTOOLS_SOURCES})
target_include_directories(artools
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/libartools/inc>
    $<INSTALL_INTERFACE:include>
    ${RAPIDJSON_INCLUDE_DIR})
# Expose the project version to the library sources (e.g. for the User-Agent).
target_compile_definitions(artools
  PUBLIC
    ARTOOLS_VERSION="${PROJECT_VERSION}")
# rapidjson is header-only: it contributes only an include directory, never a
# link library (there is no librapidjson to link against).
target_link_libraries(artools
  PUBLIC
    OpenSSL::Crypto
    OpenSSL::SSL)

# --- Executable --------------------------------------------------------------
add_executable(ar-wallet ar-wallet/main.cpp)
target_link_libraries(ar-wallet PRIVATE artools)

# --- Tests -------------------------------------------------------------------
enable_testing()
add_subdirectory(tests)

# --- Install -----------------------------------------------------------------
include(GNUInstallDirs)
install(TARGETS artools ar-wallet
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(DIRECTORY libartools/inc/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})