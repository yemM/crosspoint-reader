add_executable(ReadingStatsTest ReadingStatsTest.cpp)

target_include_directories(ReadingStatsTest PRIVATE ../../src)

target_link_libraries(ReadingStatsTest PRIVATE
  crosspoint_test_common
  GTest::gtest_main
)

gtest_discover_tests(ReadingStatsTest)
