#pragma once

#include <cstdint>

#include "util/ReadingStats.h"

// Reading time, pages and finished books for the Stats home, kept in
// /.crosspoint/reading_stats.bin.
//
// The reader reports each session: beginSession() on open, noteActivity() on
// every page turn, noteFinished() at the end-of-book screen and endSession() on
// exit (which also runs before deep sleep). Only the loop task calls in; the
// home screen reads a copy of stats().
class ReadingStatsStore {
 public:
  static ReadingStatsStore& getInstance();

  // Tracking runs only on boards that offer the Stats home.
  static bool enabled();
  // The local date, or false when the board has no clock or it was never set.
  static bool localDate(reading_stats::LocalDate& out);

  void load();

  void beginSession(const char* bookPath);
  // Credits the reading time since the previous call; countPage adds a page.
  void noteActivity(bool countPage);
  void noteFinished();
  void endSession();

  const reading_stats::Stats& stats() const { return data; }

 private:
  ReadingStatsStore() = default;

  void credit(bool countPage);
  bool saveIfDirty();

  reading_stats::Stats data;
  reading_stats::SessionClock session;
  uint32_t sessionHash = 0;
  uint32_t lastSaveMs = 0;
  bool dirty = false;
  // Set when the file on SD comes from a newer firmware: never overwrite it.
  bool readOnly = false;
};

#define READING_STATS ReadingStatsStore::getInstance()
