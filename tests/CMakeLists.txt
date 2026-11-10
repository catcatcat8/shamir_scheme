include(FetchContent)

# Pinned by version and SHA-256 of the release archive.
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/refs/tags/v1.15.2.tar.gz
  URL_HASH SHA256=7b42b4d6ed48810c5362c265a17faebe90dc2373c885e5216439d37927f02926
)
set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

add_executable(shamir_tests
  shamir_test.cpp
  feldman_test.cpp
  keys_test.cpp
)
target_link_libraries(shamir_tests PRIVATE shamir GTest::gtest_main)

include(GoogleTest)
gtest_discover_tests(shamir_tests DISCOVERY_TIMEOUT 60)

add_test(NAME cli COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/cli_test.sh $<TARGET_FILE:shamir_cli>)
