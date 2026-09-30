#pragma once

#include "UiAppHost.h"
#include "components/controls/progress-bar.h"
#include "components/media/metric-card.h"
#include "util/ReadingStats.h"

// Reading statistics for the Stats home, drawn from a snapshot taken in
// begin(), so the render task never reads the live store.
//
// With a dated clock it has two pages: this year (totals, goal, the last seven
// days, streaks) and habits (time of day, this week, all time). Without one it
// shows all-time totals only.
class ReadingStatsPanel {
 public:
  void begin();
  int pageCount() const { return dated ? 2 : 1; }
  void setPage(int page) { currentPage = page; }
  // A tap anywhere on the panel fires pageAction.
  void draw(UiAppHost::UiScreen& screen, freeink::ui::Rect rect, freeink::ui::ActionId pageAction);

  static constexpr int16_t PAGE_DOTS_HEIGHT = 8;
  // One dot per page, the current one filled, centered in rect.
  static void drawPageDots(UiAppHost::UiScreen& screen, freeink::ui::Rect rect, int count, int current);

 private:
  static constexpr int MAX_CARDS = 3;
  struct Card {
    const char* label;
    const char* value;
    const char* unit;
  };

  void drawYear(UiAppHost::UiScreen& screen, freeink::ui::Rect rect);
  void drawHabits(UiAppHost::UiScreen& screen, freeink::ui::Rect rect);
  void drawUndated(UiAppHost::UiScreen& screen, freeink::ui::Rect rect);
  // Returns the height used.
  int16_t drawCards(UiAppHost::UiScreen& screen, freeink::ui::Rect rect, const Card* cards, int count);
  int16_t drawGoal(UiAppHost::UiScreen& screen, freeink::ui::Rect rect);
  void drawWeekChart(UiAppHost::UiScreen& screen, freeink::ui::Rect rect);
  int16_t drawBuckets(UiAppHost::UiScreen& screen, freeink::ui::Rect rect);
  static int16_t drawSectionTitle(UiAppHost::UiScreen& screen, freeink::ui::Rect rect, const char* left,
                                  const char* right);
  int16_t cardHeight(UiAppHost::UiScreen& screen) const;
  // Reading time over the chart's seven days.
  uint32_t weekSeconds() const;
  // Formats a duration for a card: value into buf, unit (or null) returned.
  static const char* formatDuration(uint32_t seconds, char* buf, size_t len);

  reading_stats::Stats snapshot;
  reading_stats::LocalDate today{};
  bool dated = false;
  int currentPage = 0;
  uint16_t goalBooks = 0;
  uint32_t daySeconds[reading_stats::CHART_DAYS]{};
  uint16_t dayPages[reading_stats::CHART_DAYS]{};
  // Text and component props stay off the render task's stack.
  char values[MAX_CARDS][16]{};
  char line[32]{};
  char chartLabel[12]{};
  freeink::ui::MetricCardProps card;
  freeink::ui::ProgressBarProps bar;
};
