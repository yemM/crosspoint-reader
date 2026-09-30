add_executable(CoverCanvasTest CoverCanvasTest.cpp CoverSlotsTest.cpp)

target_include_directories(CoverCanvasTest PRIVATE ../../src)

target_link_libraries(CoverCanvasTest PRIVATE
  crosspoint_test_common
  GTest::gtest_main
)

gtest_discover_tests(CoverCanvasTest)
