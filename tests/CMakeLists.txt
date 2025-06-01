add_executable(unit_tests unit_tests.cpp)
target_compile_definitions(unit_tests PRIVATE TESTING)
target_link_libraries(unit_tests gtest gtest_main pthread)
add_test(NAME AllUnitTests COMMAND unit_tests)