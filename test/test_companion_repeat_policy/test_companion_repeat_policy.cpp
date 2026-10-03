#include "../../examples/companion_radio/RepeatPolicy.h"

#include <gtest/gtest.h>

TEST(CompanionRepeatPolicy, LegacyStandardFrequencyPreservesRepeat) {
  EXPECT_TRUE(resolveRepeatForRadioRequest(true, false, false, true));
}

TEST(CompanionRepeatPolicy, LegacyNonstandardFrequencyDisablesRepeat) {
  EXPECT_FALSE(resolveRepeatForRadioRequest(true, false, false, false));
}

TEST(CompanionRepeatPolicy, ModernRequestUsesExplicitRepeatSetting) {
  EXPECT_TRUE(resolveRepeatForRadioRequest(false, true, true, true));
  EXPECT_FALSE(resolveRepeatForRadioRequest(true, true, false, true));
}

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
