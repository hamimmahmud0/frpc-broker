cmake_minimum_required(VERSION 3.16)
project(tunnelmate C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

option(TUNNELMATE_SANITIZE "Build with ASan/UBSan" OFF)
option(TUNNELMATE_STATIC "Link fully static, for portable release binaries" OFF)

if(TUNNELMATE_STATIC)
  # Both find_package(OpenSSL) and pkg_check_modules resolve to the shared
  # library whenever one is installed, and a single .so on the link line makes
  # `-static` fail outright ("attempted static link of dynamic object"). Force
  # every lookup below to consider archives only.
  set(OPENSSL_USE_STATIC_LIBS ON)
  set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
  add_link_options(-static)
endif()

add_compile_options(-Wall -Wextra -Wpedantic -Wshadow -Wformat=2)
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
  add_compile_options(-fno-strict-aliasing)
endif()
if(TUNNELMATE_SANITIZE)
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -g)
  add_link_options(-fsanitize=address,undefined)
endif()

find_package(OpenSSL 3.2 REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBUV REQUIRED IMPORTED_TARGET libuv)

add_subdirectory(common)
add_subdirectory(broker)
add_subdirectory(agent)
add_subdirectory(peer)

enable_testing()
add_subdirectory(common/tests)
