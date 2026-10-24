#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <type_traits>

// Reading statistics model: counters, day accounting, streaks and the on-disk
// record. Kept free of SD, clock and SDK types so host tests can pin down its
// rules; ReadingStatsStore feeds it and persists it.
//
// Lifetime totals are always credited. Everything tied to a date (the year
// block, the day ring, time-of-day buckets and streaks) is credited only when
// the caller knows the local date, so a device whose clock was never set still
// counts totals.
namespace reading_stats {

constexpr uint32_t MAGIC = 0x31545352;  // "RST1"
constexpr uint16_t VERSION = 1;
// Enough days for the 7-day chart; streaks keep their own scalar state.
constexpr int DAY_SLOTS = 14;
// Books finished this year, remembered so reopening the end of a book does not
// count it twice.
constexpr int FINISHED_SLOTS = 64;
constexpr int CHART_DAYS = 7;
// A longer gap between two page turns is time away from the book (or the
// auto-sleep timeout): it is dropped, not capped.
constexpr uint32_t IDLE_LIMIT_MS = 5 * 60 * 1000;
// A day counts toward the streak once this much reading was done on it.
constexpr uint32_t STREAK_MIN_SECONDS = 60;
constexpr int32_t NO_DAY = INT32_MIN;
// Dates before this come from a clock that was never set.
constexpr int MIN_VALID_YEAR = 2024;

enum Bucket : uint8_t { Morning, Afternoon, Evening, Night, BUCKET_COUNT };

constexpr Bucket bucketForHour(const int hour) {
  if (hour >= 5 && hour < 12) return Morning;
  if (hour >= 12 && hour < 17) return Afternoon;
  if (hour >= 17 && hour < 22) return Evening;
  return Night;
}

// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's
// days-from-civil, as in HalClock.cpp).
constexpr int32_t daysFromCivil(int year, const unsigned month, const unsigned day) {
  year -= month <= 2 ? 1 : 0;
  const int era = (year >= 0 ? year : year - 399) / 400;
  const unsigned yoe = static_cast<unsigned>(year - era * 400);
  const unsigned doy = (153u * (month > 2 ? month - 3 : month + 9) + 2u) / 5u + day - 1u;
  const unsigned doe = yoe * 365u + yoe / 4u - yoe / 100u + doy;
  return era * 146097 + static_cast<int32_t>(doe) - 719468;
}

// 0 = Sunday .. 6 = Saturday. 1970-01-01 was a Thursday.
constexpr uint8_t weekdayOf(const int32_t dayNumber) {
  const int32_t w = (dayNumber + 4) % 7;
  return static_cast<uint8_t>(w < 0 ? w + 7 : w);
}

constexpr uint32_t fnv1a32(const uint8_t* bytes, const size_t len, uint32_t hash = 2166136261u) {
  for (size_t i = 0; i < len; ++i) {
    hash ^= bytes[i];
    hash *= 16777619u;
  }
  return hash;
}

inline uint32_t pathHash32(const char* path) {
  return fnv1a32(reinterpret_cast<const uint8_t*>(path), std::strlen(path));
}

struct Duration {
  uint32_t hours;
  uint32_t minutes;
};

constexpr Duration splitDuration(const uint32_t seconds) { return {seconds / 3600, (seconds / 60) % 60}; }

// Local calendar position of "now", built by the caller from its clock.
struct LocalDate {
  int16_t year = 0;
  uint8_t month = 0;
  uint8_t day = 0;
  uint8_t hour = 0;
  int32_t dayNumber = NO_DAY;
};

// month 1-12, day 1-31, hour 0-23.
constexpr LocalDate makeLocalDate(const int year, const int month, const int day, const int hour) {
  LocalDate date;
  date.year = static_cast<int16_t>(year);
  date.month = static_cast<uint8_t>(month);
  date.day = static_cast<uint8_t>(day);
  date.hour = static_cast<uint8_t>(hour);
  date.dayNumber = daysFromCivil(year, static_cast<unsigned>(month), static_cast<unsigned>(day));
  return date;
}

struct DayEntry {
  int32_t day;
  uint32_t seconds;
  uint16_t pages;
  uint16_t reserved;
};

// Persisted verbatim (little-endian, no implicit padding).
struct Data {
  uint32_t magic;
  uint16_t version;
  uint16_t size;
  uint32_t lifetimeSeconds;
  uint32_t lifetimePages;
  uint16_t lifetimeBooks;
  uint16_t year;  // 0 until the first dated reading
  uint32_t yearSeconds;
  uint32_t yearPages;
  uint16_t yearBooks;
  uint16_t currentStreak;
  uint16_t bestStreak;
  uint8_t finishedCount;
  uint8_t finishedNext;
  int32_t lastStreakDay;
  uint32_t bucketSeconds[BUCKET_COUNT];  // this year
  DayEntry days[DAY_SLOTS];              // slot = day % DAY_SLOTS, stamped with its day
  uint32_t finished[FINISHED_SLOTS];     // path hashes of this year's finished books
  uint32_t checksum;                     // FNV-1a of every byte before it
};
static_assert(std::is_trivially_copyable_v<Data>, "Data is written to SD as raw bytes");
static_assert(sizeof(DayEntry) == 12, "DayEntry layout is persisted");
static_assert(sizeof(Data) == 484, "Data layout is persisted; bump VERSION when it changes");
static_assert(offsetof(Data, checksum) == sizeof(Data) - sizeof(uint32_t), "checksum must be last");

class Stats {
 public:
  Stats() { reset(); }

  void reset() {
    d = Data{};
    d.lastStreakDay = NO_DAY;
    for (auto& entry : d.days) entry.day = NO_DAY;
  }

  const Data& data() const { return d; }

  // Credits reading time and pages. now is null when the date is unknown.
  void addReading(const uint32_t seconds, const uint32_t pages, const LocalDate* now) {
    if (seconds == 0 && pages == 0) return;
    d.lifetimeSeconds += seconds;
    d.lifetimePages += pages;
    if (now == nullptr || !rollYear(now->year)) return;
    d.yearSeconds += seconds;
    d.yearPages += pages;
    d.bucketSeconds[bucketForHour(now->hour)] += seconds;
    DayEntry& entry = dayEntry(now->dayNumber);
    entry.seconds += seconds;
    entry.pages = static_cast<uint16_t>(entry.pages + pages > UINT16_MAX ? UINT16_MAX : entry.pages + pages);
    if (entry.seconds >= STREAK_MIN_SECONDS) creditStreak(now->dayNumber);
  }

  // Counts a finished book once. True when it was newly counted.
  bool markFinished(const uint32_t pathHash, const LocalDate* now) {
    const bool dated = now != nullptr && rollYear(now->year);
    for (int i = 0; i < d.finishedCount; ++i) {
      if (d.finished[i] == pathHash) return false;
    }
    d.finished[d.finishedNext] = pathHash;
    d.finishedNext = static_cast<uint8_t>((d.finishedNext + 1) % FINISHED_SLOTS);
    if (d.finishedCount < FINISHED_SLOTS) ++d.finishedCount;
    if (d.lifetimeBooks < UINT16_MAX) ++d.lifetimeBooks;
    if (dated && d.yearBooks < UINT16_MAX) ++d.yearBooks;
    return true;
  }

  // Views: a year other than the stored one reads as empty.
  uint16_t yearBooks(const int year) const { return d.year == year ? d.yearBooks : 0; }
  uint32_t yearSeconds(const int year) const { return d.year == year ? d.yearSeconds : 0; }
  uint32_t yearPages(const int year) const { return d.year == year ? d.yearPages : 0; }
  uint32_t bucketSeconds(const int year, const Bucket bucket) const {
    return d.year == year ? d.bucketSeconds[bucket] : 0;
  }
  // Still alive while today can extend it: read today or yesterday.
  uint16_t currentStreak(const int32_t today) const {
    return d.lastStreakDay == today || d.lastStreakDay == today - 1 ? d.currentStreak : 0;
  }
  uint16_t bestStreak() const { return d.bestStreak; }

  // Last CHART_DAYS days, oldest first; index CHART_DAYS - 1 is today.
  void lastDays(const int32_t today, uint32_t (&seconds)[CHART_DAYS], uint16_t (&pages)[CHART_DAYS]) const {
    for (int i = 0; i < CHART_DAYS; ++i) {
      const int32_t day = today - (CHART_DAYS - 1) + i;
      const DayEntry& entry = d.days[slotFor(day)];
      seconds[i] = entry.day == day ? entry.seconds : 0;
      pages[i] = entry.day == day ? entry.pages : 0;
    }
  }

  static uint32_t checksumOf(const Data& data) {
    return fnv1a32(reinterpret_cast<const uint8_t*>(&data), offsetof(Data, checksum));
  }

  enum class LoadResult : uint8_t { Ok, Invalid, Newer };

  // Takes over a record read from disk. Leaves the current state untouched
  // unless it returns Ok.
  LoadResult adopt(const uint8_t* bytes, const size_t len) {
    if (len < 8) return LoadResult::Invalid;
    uint32_t magic = 0;
    uint16_t version = 0;
    std::memcpy(&magic, bytes, sizeof(magic));
    std::memcpy(&version, bytes + 4, sizeof(version));
    if (magic != MAGIC) return LoadResult::Invalid;
    if (version > VERSION) return LoadResult::Newer;
    if (version != VERSION || len != sizeof(Data)) return LoadResult::Invalid;
    Data loaded;
    std::memcpy(&loaded, bytes, sizeof(Data));
    if (loaded.size != sizeof(Data) || loaded.checksum != checksumOf(loaded)) return LoadResult::Invalid;
    if (loaded.finishedCount > FINISHED_SLOTS || loaded.finishedNext >= FINISHED_SLOTS) return LoadResult::Invalid;
    d = loaded;
    return LoadResult::Ok;
  }

  // The record to write: header and checksum filled in.
  const Data& sealed() {
    d.magic = MAGIC;
    d.version = VERSION;
    d.size = sizeof(Data);
    d.checksum = checksumOf(d);
    return d;
  }

 private:
  static int slotFor(const int32_t day) {
    const int32_t slot = day % DAY_SLOTS;
    return static_cast<int>(slot < 0 ? slot + DAY_SLOTS : slot);
  }

  DayEntry& dayEntry(const int32_t day) {
    DayEntry& entry = d.days[slotFor(day)];
    if (entry.day != day) entry = DayEntry{day, 0, 0, 0};
    return entry;
  }

  // Brings the year block to `year`. False when the date is older than the
  // stored year (a clock set back): only lifetime totals are credited then.
  bool rollYear(const int year) {
    if (year < MIN_VALID_YEAR || year > UINT16_MAX) return false;
    if (d.year == year) return true;
    if (d.year != 0 && year < d.year) return false;
    // A new year: its counters and finished books start over. Lifetime totals,
    // streaks and the day ring carry across New Year's Eve.
    const bool adoptOnly = d.year == 0;
    d.year = static_cast<uint16_t>(year);
    if (adoptOnly) return true;
    d.yearSeconds = 0;
    d.yearPages = 0;
    d.yearBooks = 0;
    std::fill(std::begin(d.bucketSeconds), std::end(d.bucketSeconds), 0u);
    d.finishedCount = 0;
    d.finishedNext = 0;
    return true;
  }

  void creditStreak(const int32_t today) {
    if (d.lastStreakDay == today) return;
    if (d.lastStreakDay == today - 1 && d.currentStreak < UINT16_MAX) {
      ++d.currentStreak;
    } else {
      // A missed day, or a clock that moved backwards.
      d.currentStreak = 1;
    }
    d.lastStreakDay = today;
    if (d.currentStreak > d.bestStreak) d.bestStreak = d.currentStreak;
  }

  Data d{};
};

// Reading time between interactions. Unsigned arithmetic keeps millis()
// wraparound harmless.
class SessionClock {
 public:
  void start(const uint32_t nowMs) {
    lastMs = nowMs;
    remainderMs = 0;
    running = true;
  }

  // Whole seconds read since the previous call; a gap longer than
  // IDLE_LIMIT_MS credits nothing.
  uint32_t creditSeconds(const uint32_t nowMs) {
    if (!running) return 0;
    const uint32_t gap = nowMs - lastMs;
    lastMs = nowMs;
    if (gap > IDLE_LIMIT_MS) return 0;
    remainderMs += gap;
    const uint32_t seconds = remainderMs / 1000;
    remainderMs %= 1000;
    return seconds;
  }

  bool active() const { return running; }
  void stop() { running = false; }

 private:
  uint32_t lastMs = 0;
  uint32_t remainderMs = 0;
  bool running = false;
};

}  // namespace reading_stats
