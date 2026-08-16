include(CTest)

add_executable(tm_common_tests
  test_common.c
)
target_link_libraries(tm_common_tests PRIVATE tmcommon)
target_include_directories(tm_common_tests PRIVATE ../include)

add_test(NAME common_tests COMMAND tm_common_tests)
