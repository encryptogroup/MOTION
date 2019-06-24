#include <gtest/gtest.h>

#define BOOST_LOG_DYN_LINK 1

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}