cmake_minimum_required(VERSION 3.16)
project(shamir_scheme VERSION 2.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

option(SHAMIR_WERROR "Treat compiler warnings as errors" OFF)
option(SHAMIR_SANITIZE "Build with AddressSanitizer and UndefinedBehaviorSanitizer" OFF)

find_package(OpenSSL 1.1.1 REQUIRED)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
  add_compile_options(-Wall -Wextra -Wpedantic -Wshadow)
  if(SHAMIR_WERROR)
    add_compile_options(-Werror)
  endif()
  if(SHAMIR_SANITIZE)
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all)
    add_link_options(-fsanitize=address,undefined)
  endif()
endif()

add_library(shamir
  src/shamir.cpp
  src/keys.cpp
  src/keccak.cpp
  src/openssl_util.cpp
)
target_include_directories(shamir PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(shamir PUBLIC OpenSSL::Crypto)

add_executable(shamir_cli src/cli.cpp)
target_link_libraries(shamir_cli PRIVATE shamir)
set_target_properties(shamir_cli PROPERTIES OUTPUT_NAME shamir)
