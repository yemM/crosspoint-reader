#include <gtest/gtest.h>

#include "util/CoverSlots.h"

TEST(CoverSlotTable, FillsEmptySlotsBeforeEvicting) {
  CoverSlotTable<3> table;
  table.beginBuild();
  EXPECT_EQ(table.claim(10), 0);
  EXPECT_EQ(table.claim(11), 1);
  EXPECT_EQ(table.claim(12), 2);
  EXPECT_EQ(table.find(11), 1);
  EXPECT_EQ(table.find(99), -1);
}

TEST(CoverSlotTable, NeverEvictsASlotOfTheCurrentBuild) {
  CoverSlotTable<2> table;
  table.beginBuild();
  ASSERT_EQ(table.claim(10), 0);
  ASSERT_EQ(table.claim(11), 1);
  // Both slots back rows of this build: a third book gets nothing rather than
  // overwriting pixels a row still points at.
  EXPECT_EQ(table.claim(12), -1);
  EXPECT_EQ(table.find(10), 0);
  EXPECT_EQ(table.find(11), 1);
}

TEST(CoverSlotTable, EvictsLeastRecentlyUsedFromEarlierBuilds) {
  CoverSlotTable<3> table;
  table.beginBuild();
  table.claim(10);
  table.claim(11);
  table.claim(12);
  table.beginBuild();
  table.touch(table.find(10));
  table.beginBuild();
  table.touch(table.find(11));
  // 12 was last used two builds ago, 10 one build ago, 11 in this build.
  const int slot = table.claim(13);
  EXPECT_EQ(slot, 2);
  EXPECT_EQ(table.find(12), -1);
  EXPECT_EQ(table.claim(14), 0);
  EXPECT_EQ(table.find(10), -1);
  EXPECT_EQ(table.claim(15), -1);
}

TEST(CoverSlotTable, TouchKeepsASlotForTheCurrentBuild) {
  CoverSlotTable<2> table;
  table.beginBuild();
  table.claim(10);
  table.claim(11);
  table.beginBuild();
  EXPECT_FALSE(table.touchedThisBuild(0));
  table.touch(0);
  EXPECT_TRUE(table.touchedThisBuild(0));
  EXPECT_EQ(table.claim(12), 1);
  EXPECT_EQ(table.keyAt(1), 12u);
}

TEST(CoverSlotTable, ClearEmptiesEverySlot) {
  CoverSlotTable<2> table;
  table.beginBuild();
  table.claim(10);
  table.clear();
  EXPECT_EQ(table.find(10), -1);
  table.beginBuild();
  EXPECT_EQ(table.claim(11), 0);
}

TEST(CoverKeyRing, RemembersKeysAndDropsTheOldestWhenFull) {
  CoverKeyRing<2> ring;
  EXPECT_FALSE(ring.contains(1));
  ring.add(1);
  ring.add(2);
  ring.add(2);  // already known: must not push 1 out
  EXPECT_TRUE(ring.contains(1));
  EXPECT_TRUE(ring.contains(2));
  ring.add(3);
  EXPECT_FALSE(ring.contains(1));
  EXPECT_TRUE(ring.contains(2));
  EXPECT_TRUE(ring.contains(3));
  ring.clear();
  EXPECT_FALSE(ring.contains(3));
}
