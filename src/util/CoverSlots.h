#pragma once

#include <array>
#include <cstdint>

// Slot bookkeeping for the Library cover cache, kept free of SD and SDK types
// so host tests can pin down its invariants.
//
// Keys are book path hashes. Slots are recycled least-recently-used first, but
// never one touched during the current build: list rows of that build still
// point at its pixels.
template <int N>
class CoverSlotTable {
 public:
  void clear() {
    slots.fill(Entry{});
    stamp = 0;
  }

  // Starts a list build; slots touched by earlier builds become recyclable.
  void beginBuild() { ++stamp; }

  int find(const uint64_t key) const {
    for (int i = 0; i < N; ++i) {
      if (slots[i].occupied && slots[i].key == key) return i;
    }
    return -1;
  }

  // Assigns a slot to a key that has none and touches it: an empty slot first,
  // else the least recently used one outside the current build. -1 when every
  // slot belongs to the current build.
  int claim(const uint64_t key) {
    int victim = -1;
    for (int i = 0; i < N; ++i) {
      if (!slots[i].occupied) {
        victim = i;
        break;
      }
      if (slots[i].lastUse == stamp) continue;
      if (victim < 0 || slots[i].lastUse < slots[victim].lastUse) victim = i;
    }
    if (victim >= 0) slots[victim] = Entry{key, stamp, true};
    return victim;
  }

  void touch(const int slot) { slots[slot].lastUse = stamp; }
  bool touchedThisBuild(const int slot) const { return slots[slot].occupied && slots[slot].lastUse == stamp; }
  uint64_t keyAt(const int slot) const { return slots[slot].key; }

 private:
  struct Entry {
    uint64_t key = 0;
    uint32_t lastUse = 0;
    bool occupied = false;
  };
  std::array<Entry, N> slots{};
  uint32_t stamp = 0;
};

// Fixed-size set of recent keys; the oldest is overwritten once full.
template <int N>
class CoverKeyRing {
 public:
  void clear() {
    count = 0;
    next = 0;
  }

  bool contains(const uint64_t key) const {
    for (int i = 0; i < count; ++i) {
      if (keys[i] == key) return true;
    }
    return false;
  }

  void add(const uint64_t key) {
    if (contains(key)) return;
    keys[next] = key;
    next = (next + 1) % N;
    if (count < N) ++count;
  }

 private:
  std::array<uint64_t, N> keys{};
  int count = 0;
  int next = 0;
};
