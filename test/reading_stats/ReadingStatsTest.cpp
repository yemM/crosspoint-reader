#include <gtest/gtest.h>

#include <vector>

#include "util/ReadingStats.h"

using namespace reading_stats;

namespace {
LocalDate on(const int year, const int month, const int day, const int hour = 20) {
  return makeLocalDate(year, month, day, hour);
}
}  // namespace

TEST(ReadingStatsCalendar, DayNumbersAndWeekdays) {
  EXPECT_EQ(daysFromCivil(1970, 1, 1), 0);
  EXPECT_EQ(weekdayOf(0), 4);                                            // Thursday
  EXPECT_EQ(daysFromCivil(2024, 3, 1) - daysFromCivil(2024, 2, 28), 2);  // leap day
  EXPECT_EQ(daysFromCivil(2025, 3, 1) - daysFromCivil(2025, 2, 28), 1);
  EXPECT_EQ(weekdayOf(daysFromCivil(2026, 9, 29)), 2);  // Tuesday
  EXPECT_EQ(weekdayOf(-1), 3);                          // 1969-12-31, Wednesday
}

TEST(ReadingStatsCalendar, BucketBoundaries) {
  EXPECT_EQ(bucketForHour(4), Night);
  EXPECT_EQ(bucketForHour(5), Morning);
  EXPECT_EQ(bucketForHour(11), Morning);
  EXPECT_EQ(bucketForHour(12), Afternoon);
  EXPECT_EQ(bucketForHour(16), Afternoon);
  EXPECT_EQ(bucketForHour(17), Evening);
  EXPECT_EQ(bucketForHour(21), Evening);
  EXPECT_EQ(bucketForHour(22), Night);
  EXPECT_EQ(bucketForHour(0), Night);
}

TEST(ReadingStatsCalendar, SplitDuration) {
  const Duration d = splitDuration(3 * 3600 + 25 * 60 + 59);
  EXPECT_EQ(d.hours, 3u);
  EXPECT_EQ(d.minutes, 25u);
}

TEST(SessionClock, CreditsWithinTheIdleLimitAndCarriesMilliseconds) {
  SessionClock clock;
  EXPECT_EQ(clock.creditSeconds(1000), 0u);  // not started
  clock.start(1000);
  EXPECT_EQ(clock.creditSeconds(2500), 1u);  // 1.5 s, 500 ms kept
  EXPECT_EQ(clock.creditSeconds(3000), 1u);  // 0.5 s + 500 ms
  EXPECT_EQ(clock.creditSeconds(3000 + IDLE_LIMIT_MS), 300u);
}

TEST(SessionClock, DropsGapsLongerThanTheIdleLimit) {
  SessionClock clock;
  clock.start(0);
  EXPECT_EQ(clock.creditSeconds(IDLE_LIMIT_MS + 1), 0u);
  EXPECT_EQ(clock.creditSeconds(IDLE_LIMIT_MS + 1 + 30000), 30u);
  clock.stop();
  EXPECT_FALSE(clock.active());
  EXPECT_EQ(clock.creditSeconds(IDLE_LIMIT_MS + 1 + 60000), 0u);
}

TEST(SessionClock, SurvivesMillisWraparound) {
  SessionClock clock;
  clock.start(UINT32_MAX - 999);
  EXPECT_EQ(clock.creditSeconds(2000), 3u);
}

TEST(ReadingStats, UndatedReadingOnlyTouchesLifetimeTotals) {
  Stats stats;
  stats.addReading(120, 4, nullptr);
  EXPECT_EQ(stats.data().lifetimeSeconds, 120u);
  EXPECT_EQ(stats.data().lifetimePages, 4u);
  EXPECT_EQ(stats.data().year, 0);
  EXPECT_EQ(stats.bestStreak(), 0);
  EXPECT_TRUE(stats.markFinished(1, nullptr));
  EXPECT_EQ(stats.data().lifetimeBooks, 1);
  EXPECT_EQ(stats.data().yearBooks, 0);
}

TEST(ReadingStats, UnsetClockYearCountsAsUndated) {
  Stats stats;
  const LocalDate epoch = on(2000, 1, 1);
  stats.addReading(60, 1, &epoch);
  EXPECT_EQ(stats.data().lifetimeSeconds, 60u);
  EXPECT_EQ(stats.data().year, 0);
}

TEST(ReadingStats, DatedReadingFillsYearDayAndBucket) {
  Stats stats;
  const LocalDate morning = on(2026, 9, 29, 8);
  const LocalDate evening = on(2026, 9, 29, 21);
  stats.addReading(90, 3, &morning);
  stats.addReading(30, 1, &evening);
  EXPECT_EQ(stats.yearSeconds(2026), 120u);
  EXPECT_EQ(stats.yearPages(2026), 4u);
  EXPECT_EQ(stats.yearSeconds(2025), 0u);
  EXPECT_EQ(stats.bucketSeconds(2026, Morning), 90u);
  EXPECT_EQ(stats.bucketSeconds(2026, Evening), 30u);

  uint32_t seconds[CHART_DAYS];
  uint16_t pages[CHART_DAYS];
  stats.lastDays(morning.dayNumber, seconds, pages);
  EXPECT_EQ(seconds[CHART_DAYS - 1], 120u);
  EXPECT_EQ(pages[CHART_DAYS - 1], 4);
  EXPECT_EQ(seconds[0], 0u);
}

TEST(ReadingStats, ChartOrdersDaysAndIgnoresStaleSlots) {
  Stats stats;
  const LocalDate d1 = on(2026, 9, 1);
  const LocalDate d2 = on(2026, 9, 14);
  const LocalDate d3 = on(2026, 9, 15);  // 14 days after d1: reuses its slot
  stats.addReading(60, 1, &d1);
  stats.addReading(120, 2, &d2);
  stats.addReading(180, 3, &d3);

  uint32_t seconds[CHART_DAYS];
  uint16_t pages[CHART_DAYS];
  stats.lastDays(d3.dayNumber, seconds, pages);
  EXPECT_EQ(seconds[CHART_DAYS - 1], 180u);
  EXPECT_EQ(seconds[CHART_DAYS - 2], 120u);
  // Two weeks later, nothing was read in the last week.
  stats.lastDays(d3.dayNumber + 14, seconds, pages);
  for (const uint32_t s : seconds) EXPECT_EQ(s, 0u);
}

TEST(ReadingStats, ForwardYearChangeResetsTheYearBlockOnly) {
  Stats stats;
  const LocalDate dec = on(2025, 12, 31, 23);
  const LocalDate jan = on(2026, 1, 1, 0);
  stats.addReading(600, 10, &dec);
  stats.markFinished(42, &dec);
  stats.addReading(60, 1, &jan);
  EXPECT_EQ(stats.data().year, 2026);
  EXPECT_EQ(stats.yearSeconds(2026), 60u);
  EXPECT_EQ(stats.yearBooks(2026), 0);
  EXPECT_EQ(stats.bucketSeconds(2026, Night), 60u);
  EXPECT_EQ(stats.data().lifetimeSeconds, 660u);
  EXPECT_EQ(stats.data().lifetimeBooks, 1);
  // Streak carries across New Year's Eve.
  EXPECT_EQ(stats.currentStreak(jan.dayNumber), 2);
  // Last year's finished books may be counted again this year.
  EXPECT_TRUE(stats.markFinished(42, &jan));
  EXPECT_EQ(stats.yearBooks(2026), 1);
}

TEST(ReadingStats, ClockSetBackOnlyCreditsLifetime) {
  Stats stats;
  const LocalDate now = on(2026, 3, 1);
  const LocalDate past = on(2025, 6, 1);
  stats.addReading(60, 1, &now);
  stats.addReading(60, 1, &past);
  EXPECT_EQ(stats.data().year, 2026);
  EXPECT_EQ(stats.yearSeconds(2026), 60u);
  EXPECT_EQ(stats.data().lifetimeSeconds, 120u);
}

TEST(ReadingStats, StreakNeedsAMinuteAndConsecutiveDays) {
  Stats stats;
  const LocalDate d1 = on(2026, 9, 1);
  const LocalDate d2 = on(2026, 9, 2);
  const LocalDate d3 = on(2026, 9, 3);
  const LocalDate d5 = on(2026, 9, 5);

  stats.addReading(STREAK_MIN_SECONDS - 1, 1, &d1);
  EXPECT_EQ(stats.currentStreak(d1.dayNumber), 0);
  stats.addReading(1, 0, &d1);
  EXPECT_EQ(stats.currentStreak(d1.dayNumber), 1);
  stats.addReading(600, 0, &d1);  // same day: no double count
  EXPECT_EQ(stats.currentStreak(d1.dayNumber), 1);

  stats.addReading(60, 0, &d2);
  stats.addReading(60, 0, &d3);
  EXPECT_EQ(stats.currentStreak(d3.dayNumber), 3);
  // Still alive the next day before reading, broken the day after.
  EXPECT_EQ(stats.currentStreak(d3.dayNumber + 1), 3);
  EXPECT_EQ(stats.currentStreak(d5.dayNumber), 0);

  stats.addReading(60, 0, &d5);
  EXPECT_EQ(stats.currentStreak(d5.dayNumber), 1);
  EXPECT_EQ(stats.bestStreak(), 3);
}

TEST(ReadingStats, StreakRestartsWhenTheClockMovesBackADay) {
  Stats stats;
  const LocalDate d2 = on(2026, 9, 2);
  const LocalDate d1 = on(2026, 9, 1);
  stats.addReading(60, 0, &d2);
  stats.addReading(60, 0, &d1);
  EXPECT_EQ(stats.currentStreak(d1.dayNumber), 1);
  EXPECT_EQ(stats.bestStreak(), 1);
}

TEST(ReadingStats, FinishedBooksAreCountedOnce) {
  Stats stats;
  const LocalDate now = on(2026, 9, 29);
  EXPECT_TRUE(stats.markFinished(pathHash32("/Books/a.epub"), &now));
  EXPECT_FALSE(stats.markFinished(pathHash32("/Books/a.epub"), &now));
  EXPECT_TRUE(stats.markFinished(pathHash32("/Books/b.epub"), &now));
  EXPECT_EQ(stats.yearBooks(2026), 2);
  EXPECT_EQ(stats.data().lifetimeBooks, 2);
}

TEST(ReadingStats, FinishedRingForgetsTheOldestWhenFull) {
  Stats stats;
  const LocalDate now = on(2026, 9, 29);
  for (uint32_t i = 0; i < FINISHED_SLOTS; ++i) stats.markFinished(1000 + i, &now);
  EXPECT_FALSE(stats.markFinished(1000, &now));
  EXPECT_TRUE(stats.markFinished(5000, &now));  // overwrites 1000
  EXPECT_TRUE(stats.markFinished(1000, &now));
  EXPECT_EQ(stats.yearBooks(2026), FINISHED_SLOTS + 2);
}

TEST(ReadingStats, SealedRecordRoundTrips) {
  Stats stats;
  const LocalDate now = on(2026, 9, 29);
  stats.addReading(3600, 50, &now);
  stats.markFinished(7, &now);
  const Data record = stats.sealed();

  std::vector<uint8_t> bytes(sizeof(Data));
  std::memcpy(bytes.data(), &record, sizeof(Data));
  Stats loaded;
  ASSERT_EQ(loaded.adopt(bytes.data(), bytes.size()), Stats::LoadResult::Ok);
  EXPECT_EQ(loaded.yearSeconds(2026), 3600u);
  EXPECT_EQ(loaded.yearBooks(2026), 1);
  EXPECT_FALSE(loaded.markFinished(7, &now));
  EXPECT_EQ(loaded.currentStreak(now.dayNumber), 1);
}

TEST(ReadingStats, RejectsCorruptTruncatedAndForeignRecords) {
  Stats stats;
  const LocalDate now = on(2026, 9, 29);
  stats.addReading(60, 1, &now);
  const Data record = stats.sealed();
  std::vector<uint8_t> bytes(sizeof(Data));
  std::memcpy(bytes.data(), &record, sizeof(Data));

  Stats target;
  std::vector<uint8_t> corrupt = bytes;
  corrupt[20] ^= 0x01;
  EXPECT_EQ(target.adopt(corrupt.data(), corrupt.size()), Stats::LoadResult::Invalid);
  EXPECT_EQ(target.adopt(bytes.data(), bytes.size() - 1), Stats::LoadResult::Invalid);
  EXPECT_EQ(target.adopt(bytes.data(), 4), Stats::LoadResult::Invalid);

  std::vector<uint8_t> foreign = bytes;
  foreign[0] = 'X';
  EXPECT_EQ(target.adopt(foreign.data(), foreign.size()), Stats::LoadResult::Invalid);
  // A failed adopt keeps the current state.
  EXPECT_EQ(target.data().lifetimeSeconds, 0u);
}

TEST(ReadingStats, ReportsRecordsFromANewerFirmware) {
  Stats stats;
  Data record = stats.sealed();
  record.version = VERSION + 1;
  std::vector<uint8_t> bytes(sizeof(Data));
  std::memcpy(bytes.data(), &record, sizeof(Data));
  Stats target;
  EXPECT_EQ(target.adopt(bytes.data(), bytes.size()), Stats::LoadResult::Newer);
}
