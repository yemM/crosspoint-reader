#include "ReadingStatsStore.h"

#include <Arduino.h>
#include <HalClock.h>
#include <HalMemory.h>
#include <HalStorage.h>
#include <Logging.h>

#include <cstring>
#include <ctime>

#include "activities/reader/ProgressFile.h"

namespace {
constexpr const char* STATS_PATH = "/.crosspoint/reading_stats.bin";
constexpr const char* STATS_TMP_PATH = "/.crosspoint/reading_stats.bin.tmp";
constexpr uint32_t PERIODIC_SAVE_MS = 10 * 60 * 1000;

// File I/O buffer, static to stay off the loop task's stack.
uint8_t recordBuffer[sizeof(reading_stats::Data)];

reading_stats::Stats::LoadResult readRecord(const char* path, reading_stats::Stats& stats) {
  if (!Storage.exists(path)) return reading_stats::Stats::LoadResult::Invalid;
  HalFile file;
  if (!Storage.openFileForRead("RST", path, file)) return reading_stats::Stats::LoadResult::Invalid;
  const size_t size = file.fileSize();
  if (size != sizeof(recordBuffer)) {
    // Not this firmware's layout. The header still tells a record from a newer
    // firmware apart from a broken file; adopt() never accepts it.
    const int headerLen = file.read(recordBuffer, size < 8 ? size : 8);
    return stats.adopt(recordBuffer, headerLen > 0 ? static_cast<size_t>(headerLen) : 0);
  }
  if (file.read(recordBuffer, size) != static_cast<int>(size)) return reading_stats::Stats::LoadResult::Invalid;
  return stats.adopt(recordBuffer, size);
}
}  // namespace

ReadingStatsStore& ReadingStatsStore::getInstance() {
  static ReadingStatsStore instance;
  return instance;
}

bool ReadingStatsStore::enabled() { return HalMemory::getPsramHeap().totalBytes > 0; }

bool ReadingStatsStore::localDate(reading_stats::LocalDate& out) {
  struct tm local{};
  if (!halClock.localTime(local)) return false;
  const int year = local.tm_year + 1900;
  if (year < reading_stats::MIN_VALID_YEAR) return false;
  out = reading_stats::makeLocalDate(year, local.tm_mon + 1, local.tm_mday, local.tm_hour);
  return true;
}

void ReadingStatsStore::load() {
  if (!enabled()) return;
  using LoadResult = reading_stats::Stats::LoadResult;
  LoadResult result = readRecord(STATS_PATH, data);
  // A crash between the remove and the rename of an atomic write leaves only
  // the temp file behind.
  if (result == LoadResult::Invalid) result = readRecord(STATS_TMP_PATH, data);
  readOnly = result == LoadResult::Newer;
  if (result == LoadResult::Ok) {
    LOG_INF("RST", "Reading stats loaded");
  } else if (readOnly) {
    LOG_ERR("RST", "Reading stats written by a newer firmware; not recording");
  } else if (Storage.exists(STATS_PATH)) {
    LOG_ERR("RST", "Reading stats unreadable; starting over");
  }
}

void ReadingStatsStore::beginSession(const char* bookPath) {
  if (!enabled() || readOnly) return;
  sessionHash = reading_stats::pathHash32(bookPath);
  session.start(millis());
  lastSaveMs = millis();
}

void ReadingStatsStore::credit(const bool countPage) {
  const uint32_t seconds = session.creditSeconds(millis());
  if (seconds == 0 && !countPage) return;
  reading_stats::LocalDate today;
  const bool dated = localDate(today);
  data.addReading(seconds, countPage ? 1 : 0, dated ? &today : nullptr);
  dirty = true;
}

void ReadingStatsStore::noteActivity(const bool countPage) {
  if (!session.active()) return;
  credit(countPage);
  if (millis() - lastSaveMs >= PERIODIC_SAVE_MS) saveIfDirty();
}

void ReadingStatsStore::noteFinished() {
  if (!session.active()) return;
  reading_stats::LocalDate today;
  const bool dated = localDate(today);
  if (data.markFinished(sessionHash, dated ? &today : nullptr)) {
    LOG_INF("RST", "Book finished");
    dirty = true;
  }
}

void ReadingStatsStore::endSession() {
  if (!session.active()) return;
  credit(false);
  session.stop();
  saveIfDirty();
}

bool ReadingStatsStore::saveIfDirty() {
  lastSaveMs = millis();
  if (!dirty || readOnly) return true;
  const reading_stats::Data& record = data.sealed();
  std::memcpy(recordBuffer, &record, sizeof(recordBuffer));
  if (!ProgressFile::writeAtomic(STATS_PATH, STATS_TMP_PATH, recordBuffer, sizeof(recordBuffer))) {
    LOG_ERR("RST", "Could not save reading stats");
    return false;
  }
  dirty = false;
  return true;
}
