#include "ReadingStatsPanel.h"

#include <I18n.h>

#include <algorithm>
#include <cstdio>
#include <iterator>
#include <numeric>

#include "CrossPointSettings.h"
#include "ReadingStatsStore.h"

namespace fui = freeink::ui;
namespace rs = reading_stats;

namespace {
constexpr int16_t DOT_SIZE = 6;
constexpr int16_t GOAL_BAR_HEIGHT = 8;
constexpr int16_t BUCKET_BAR_HEIGHT = 10;
constexpr int16_t MIN_CHART_HEIGHT = 80;

constexpr StrId WEEKDAY_LABELS[] = {StrId::STR_WEEKDAY_SUN, StrId::STR_WEEKDAY_MON, StrId::STR_WEEKDAY_TUE,
                                    StrId::STR_WEEKDAY_WED, StrId::STR_WEEKDAY_THU, StrId::STR_WEEKDAY_FRI,
                                    StrId::STR_WEEKDAY_SAT};
constexpr StrId BUCKET_LABELS[] = {StrId::STR_STATS_MORNING, StrId::STR_STATS_AFTERNOON, StrId::STR_STATS_EVENING,
                                   StrId::STR_STATS_NIGHT};
static_assert(std::size(BUCKET_LABELS) == rs::BUCKET_COUNT);

// Side-by-side columns once the panel is much wider than tall (landscape).
bool twoColumns(const fui::Rect rect) { return rect.width > 2 * rect.height; }

fui::TextStyle bold(fui::TextStyle style) {
  style.bold = true;
  return style;
}

fui::TextStyle aligned(fui::TextStyle style, const fui::TextAlign align) {
  style.align = align;
  return style;
}
}  // namespace

void ReadingStatsPanel::begin() {
  snapshot = READING_STATS.stats();
  dated = ReadingStatsStore::localDate(today);
  currentPage = 0;
  card.padding = fui::Insets{6, 4, 6, 4};
  card.gap = 2;
  const uint8_t goal = SETTINGS.readingGoal;
  goalBooks =
      goal < std::size(CrossPointSettings::READING_GOAL_BOOKS) ? CrossPointSettings::READING_GOAL_BOOKS[goal] : 0;
  if (dated) snapshot.lastDays(today.dayNumber, daySeconds, dayPages);
}

void ReadingStatsPanel::draw(UiAppHost::UiScreen& screen, const fui::Rect rect, const fui::ActionId pageAction) {
  if (rect.empty()) return;
  screen.frame().hit(rect, pageAction, 0, fui::InputTouch);
  if (!dated) {
    drawUndated(screen, rect);
  } else if (currentPage == 0) {
    drawYear(screen, rect);
  } else {
    drawHabits(screen, rect);
  }
}

int16_t ReadingStatsPanel::cardHeight(UiAppHost::UiScreen& screen) const {
  const auto& theme = screen.theme();
  return static_cast<int16_t>(card.padding.top + card.padding.bottom +
                              screen.target().lineHeight(theme.smallText.font) + card.gap +
                              screen.target().lineHeight(theme.titleText.font));
}

int16_t ReadingStatsPanel::drawCards(UiAppHost::UiScreen& screen, const fui::Rect rect, const Card* cards,
                                     const int count) {
  const auto& theme = screen.theme();
  card.labelText = theme.smallText;
  card.valueText = bold(theme.titleText);
  card.styles = fui::StyleSet{};
  card.styles.normal.background = fui::Paint::solid(fui::Color::White);
  card.styles.normal.border = fui::Paint::solid(fui::Color::Black);
  card.styles.normal.borderWidth = 1;
  card.styles.normal.radius = theme.listRowRadius;
  card.styles.explicitlySet = true;
  const int16_t height = cardHeight(screen);
  const int16_t gap = theme.spaceSm;
  const int16_t width = static_cast<int16_t>((rect.width - gap * (count - 1)) / count);
  for (int i = 0; i < count; ++i) {
    card.label = cards[i].label;
    card.value = cards[i].value;
    card.unit = cards[i].unit;
    const fui::Rect cell{static_cast<int16_t>(rect.x + i * (width + gap)), rect.y, width, height};
    fui::metricCard(screen.frame(), cell, card);
  }
  return height;
}

uint32_t ReadingStatsPanel::weekSeconds() const {
  return std::accumulate(std::begin(daySeconds), std::end(daySeconds), uint32_t{0});
}

int16_t ReadingStatsPanel::drawSectionTitle(UiAppHost::UiScreen& screen, const fui::Rect rect, const char* left,
                                            const char* right) {
  const auto& theme = screen.theme();
  const int16_t height = screen.target().lineHeight(theme.smallText.font);
  const fui::Rect row{rect.x, rect.y, rect.width, height};
  if (right) screen.target().text(row, right, aligned(theme.smallText, fui::TextAlign::Right));
  if (left) {
    const int16_t rightWidth =
        right ? static_cast<int16_t>(screen.target().measureText(theme.smallText.font, right, theme.smallText).width +
                                     theme.spaceMd)
              : 0;
    screen.target().text(fui::Rect{rect.x, rect.y, static_cast<int16_t>(rect.width - rightWidth), height}, left,
                         bold(theme.smallText));
  }
  return height;
}

const char* ReadingStatsPanel::formatDuration(const uint32_t seconds, char* buf, const size_t len) {
  const rs::Duration d = rs::splitDuration(seconds);
  if (d.hours == 0) {
    snprintf(buf, len, "%u", static_cast<unsigned>(d.minutes));
    return tr(STR_UNIT_MINUTES);
  }
  if (d.hours < 10) {
    snprintf(buf, len, "%u%s%02u", static_cast<unsigned>(d.hours), tr(STR_UNIT_HOURS),
             static_cast<unsigned>(d.minutes));
    return nullptr;
  }
  snprintf(buf, len, "%u", static_cast<unsigned>(d.hours));
  return tr(STR_UNIT_HOURS);
}

void ReadingStatsPanel::drawYear(UiAppHost::UiScreen& screen, const fui::Rect rect) {
  const auto& theme = screen.theme();
  const int16_t gap = theme.spaceMd;
  const bool columns = twoColumns(rect);
  fui::Rect left = rect;
  fui::Rect chart = rect;
  if (columns) {
    left.width = static_cast<int16_t>(rect.width * 11 / 20);
    chart.x = static_cast<int16_t>(left.right() + theme.spaceLg);
    chart.width = static_cast<int16_t>(rect.right() - chart.x);
  }

  int16_t y = left.y;
  y = static_cast<int16_t>(
      y + drawSectionTitle(screen, fui::Rect{left.x, y, left.width, 0}, tr(STR_STATS_THIS_YEAR), nullptr) +
      theme.spaceSm);
  snprintf(values[0], sizeof(values[0]), "%u", static_cast<unsigned>(snapshot.yearBooks(today.year)));
  const char* timeUnit = formatDuration(snapshot.yearSeconds(today.year), values[1], sizeof(values[1]));
  snprintf(values[2], sizeof(values[2]), "%lu", static_cast<unsigned long>(snapshot.yearPages(today.year)));
  const Card totals[] = {{tr(STR_STATS_BOOKS), values[0], nullptr},
                         {tr(STR_STATS_TIME), values[1], timeUnit},
                         {tr(STR_STATS_PAGES), values[2], nullptr}};
  y = static_cast<int16_t>(y + drawCards(screen, fui::Rect{left.x, y, left.width, 0}, totals, 3) + gap);

  if (goalBooks > 0) {
    y = static_cast<int16_t>(y + drawGoal(screen, fui::Rect{left.x, y, left.width, 0}) + gap);
  }

  // Streaks close the column; in a single column the chart takes the space
  // left between them and the goal, and they give way when it gets too tight.
  const uint16_t current = snapshot.currentStreak(today.dayNumber);
  const uint16_t best = snapshot.bestStreak();
  snprintf(values[0], sizeof(values[0]), "%u", static_cast<unsigned>(current));
  snprintf(values[1], sizeof(values[1]), "%u", static_cast<unsigned>(best));
  const Card streaks[] = {{tr(STR_STATS_STREAK), values[0], current == 1 ? tr(STR_STATS_DAY) : tr(STR_STATS_DAYS)},
                          {tr(STR_STATS_BEST_STREAK), values[1], best == 1 ? tr(STR_STATS_DAY) : tr(STR_STATS_DAYS)}};
  const int16_t streakHeight = cardHeight(screen);
  if (columns) {
    drawCards(screen, fui::Rect{left.x, y, left.width, 0}, streaks, 2);
    drawWeekChart(screen, chart);
    return;
  }
  const bool showStreaks = rect.bottom() - y - streakHeight - gap >= MIN_CHART_HEIGHT;
  const int16_t chartBottom = showStreaks ? static_cast<int16_t>(rect.bottom() - streakHeight - gap) : rect.bottom();
  drawWeekChart(screen, fui::Rect{rect.x, y, rect.width, static_cast<int16_t>(chartBottom - y)});
  if (showStreaks) {
    drawCards(screen, fui::Rect{rect.x, static_cast<int16_t>(rect.bottom() - streakHeight), rect.width, 0}, streaks, 2);
  }
}

int16_t ReadingStatsPanel::drawGoal(UiAppHost::UiScreen& screen, const fui::Rect rect) {
  const auto& theme = screen.theme();
  const uint16_t done = snapshot.yearBooks(today.year);
  snprintf(line, sizeof(line), "%u / %u", static_cast<unsigned>(done), static_cast<unsigned>(goalBooks));
  const int16_t titleHeight = drawSectionTitle(screen, rect, tr(STR_STATS_GOAL), line);
  bar = fui::ProgressBarProps{};
  bar.value = std::min<int32_t>(done, goalBooks);
  bar.max = goalBooks;
  bar.track = fui::Paint::dither(fui::Color::LightGray);
  bar.fill = fui::Paint::solid(fui::Color::Black);
  bar.border = fui::Paint::solid(fui::Color::Black);
  bar.borderWidth = 1;
  bar.minFill = 2;
  const int16_t barY = static_cast<int16_t>(rect.y + titleHeight + theme.spaceSm);
  fui::progressBar(screen.frame(), fui::Rect{rect.x, barY, rect.width, GOAL_BAR_HEIGHT}, bar);
  return static_cast<int16_t>(titleHeight + theme.spaceSm + GOAL_BAR_HEIGHT);
}

void ReadingStatsPanel::drawWeekChart(UiAppHost::UiScreen& screen, const fui::Rect rect) {
  const auto& theme = screen.theme();
  auto& target = screen.target();
  const int16_t smallHeight = target.lineHeight(theme.smallText.font);

  const uint32_t maxSeconds = *std::max_element(std::begin(daySeconds), std::end(daySeconds));
  const char* unit = formatDuration(weekSeconds(), chartLabel, sizeof(chartLabel));
  if (unit) {
    snprintf(line, sizeof(line), "%s %s", chartLabel, unit);
  } else {
    snprintf(line, sizeof(line), "%s", chartLabel);
  }
  const int16_t titleHeight = drawSectionTitle(screen, rect, tr(STR_STATS_LAST_7_DAYS), line);

  // Weekday labels under the baseline, minute labels above each bar.
  const int16_t baseline = static_cast<int16_t>(rect.bottom() - smallHeight - theme.spaceXs);
  const int16_t barTop = static_cast<int16_t>(rect.y + titleHeight + theme.spaceSm + smallHeight + theme.spaceXs);
  const int16_t barArea = static_cast<int16_t>(baseline - barTop);
  if (barArea <= 0) return;
  const auto ink = fui::Paint::solid(fui::Color::Black);
  target.line(fui::Point{rect.x, baseline}, fui::Point{static_cast<int16_t>(rect.right() - 1), baseline}, 1, ink);

  const int16_t columnWidth = static_cast<int16_t>(rect.width / rs::CHART_DAYS);
  const int16_t barWidth = static_cast<int16_t>(columnWidth * 3 / 5);
  const auto labelStyle = aligned(theme.smallText, fui::TextAlign::Center);
  for (int i = 0; i < rs::CHART_DAYS; ++i) {
    const bool isToday = i == rs::CHART_DAYS - 1;
    const int16_t x = static_cast<int16_t>(rect.x + i * columnWidth);
    const int32_t day = today.dayNumber - (rs::CHART_DAYS - 1) + i;
    target.text(fui::Rect{x, static_cast<int16_t>(baseline + theme.spaceXs), columnWidth, smallHeight},
                I18N.get(WEEKDAY_LABELS[rs::weekdayOf(day)]), isToday ? bold(labelStyle) : labelStyle);
    if (daySeconds[i] == 0 || maxSeconds == 0) continue;
    const int16_t height = static_cast<int16_t>(
        std::max<int64_t>(2, static_cast<int64_t>(daySeconds[i]) * barArea / static_cast<int64_t>(maxSeconds)));
    const int16_t top = static_cast<int16_t>(baseline - height);
    target.fill(fui::Rect{static_cast<int16_t>(x + (columnWidth - barWidth) / 2), top, barWidth, height},
                isToday ? ink : fui::Paint::dither(fui::Color::DarkGray));
    const uint32_t minutes = daySeconds[i] / 60;
    if (minutes == 0) continue;
    snprintf(chartLabel, sizeof(chartLabel), "%lu", static_cast<unsigned long>(minutes));
    target.text(fui::Rect{x, static_cast<int16_t>(top - smallHeight - theme.spaceXs), columnWidth, smallHeight},
                chartLabel, labelStyle);
  }
  if (maxSeconds == 0) {
    auto message = aligned(theme.smallText, fui::TextAlign::Center);
    message.maxLines = 2;
    target.text(fui::Rect{rect.x, static_cast<int16_t>(barTop + (barArea - 2 * smallHeight) / 2), rect.width,
                          static_cast<int16_t>(2 * smallHeight)},
                tr(STR_STATS_EMPTY), message);
  }
}

int16_t ReadingStatsPanel::drawBuckets(UiAppHost::UiScreen& screen, const fui::Rect rect) {
  const auto& theme = screen.theme();
  auto& target = screen.target();
  const int16_t titleHeight = drawSectionTitle(screen, rect, tr(STR_STATS_WHEN), nullptr);
  const int16_t rowHeight = target.lineHeight(theme.smallText.font);

  uint32_t total = 0;
  int16_t labelWidth = 0;
  for (int b = 0; b < rs::BUCKET_COUNT; ++b) {
    total += snapshot.bucketSeconds(today.year, static_cast<rs::Bucket>(b));
    labelWidth = std::max(labelWidth,
                          target.measureText(theme.smallText.font, I18N.get(BUCKET_LABELS[b]), theme.smallText).width);
  }
  const int16_t percentWidth = target.measureText(theme.smallText.font, "100%", theme.smallText).width;
  const int16_t barX = static_cast<int16_t>(rect.x + labelWidth + theme.spaceMd);
  const int16_t barWidth = static_cast<int16_t>(rect.right() - percentWidth - theme.spaceMd - barX);

  bar = fui::ProgressBarProps{};
  bar.track = fui::Paint::dither(fui::Color::LightGray);
  bar.fill = fui::Paint::solid(fui::Color::Black);
  bar.max = static_cast<int32_t>(std::min<uint32_t>(total, INT32_MAX));
  bar.minFill = 2;
  int16_t y = static_cast<int16_t>(rect.y + titleHeight + theme.spaceSm);
  for (int b = 0; b < rs::BUCKET_COUNT; ++b) {
    const uint32_t seconds = snapshot.bucketSeconds(today.year, static_cast<rs::Bucket>(b));
    target.text(fui::Rect{rect.x, y, labelWidth, rowHeight}, I18N.get(BUCKET_LABELS[b]), theme.smallText);
    bar.value = static_cast<int32_t>(std::min<uint32_t>(seconds, INT32_MAX));
    if (barWidth > 0) {
      fui::progressBar(
          screen.frame(),
          fui::Rect{barX, static_cast<int16_t>(y + (rowHeight - BUCKET_BAR_HEIGHT) / 2), barWidth, BUCKET_BAR_HEIGHT},
          bar);
    }
    const unsigned percent =
        total > 0 ? static_cast<unsigned>((static_cast<uint64_t>(seconds) * 100 + total / 2) / total) : 0;
    snprintf(line, sizeof(line), "%u%%", percent);
    target.text(fui::Rect{static_cast<int16_t>(rect.right() - percentWidth), y, percentWidth, rowHeight}, line,
                aligned(theme.smallText, fui::TextAlign::Right));
    y = static_cast<int16_t>(y + rowHeight + theme.spaceSm);
  }
  return static_cast<int16_t>(y - theme.spaceSm - rect.y);
}

void ReadingStatsPanel::drawHabits(UiAppHost::UiScreen& screen, const fui::Rect rect) {
  const auto& theme = screen.theme();
  const int16_t gap = theme.spaceLg;
  const bool columns = twoColumns(rect);
  fui::Rect first = rect;
  fui::Rect second = rect;
  if (columns) {
    first.width = static_cast<int16_t>((rect.width - theme.spaceLg) / 2);
    second.x = static_cast<int16_t>(first.right() + theme.spaceLg);
    second.width = static_cast<int16_t>(rect.right() - second.x);
  }
  const int16_t bucketsHeight = drawBuckets(screen, first);
  if (!columns) second.y = static_cast<int16_t>(rect.y + bucketsHeight + gap);

  int16_t y = second.y;
  const uint32_t weekTotal = weekSeconds();
  const char* weekUnit = formatDuration(weekTotal, values[0], sizeof(values[0]));
  const char* averageUnit = formatDuration(weekTotal / rs::CHART_DAYS, values[1], sizeof(values[1]));
  const Card week[] = {{tr(STR_STATS_THIS_WEEK), values[0], weekUnit},
                       {tr(STR_STATS_DAILY_AVERAGE), values[1], averageUnit}};
  y = static_cast<int16_t>(y + drawCards(screen, fui::Rect{second.x, y, second.width, 0}, week, 2) + gap);

  y = static_cast<int16_t>(
      y + drawSectionTitle(screen, fui::Rect{second.x, y, second.width, 0}, tr(STR_STATS_ALL_TIME), nullptr) +
      theme.spaceSm);
  const auto& data = snapshot.data();
  snprintf(values[0], sizeof(values[0]), "%u", static_cast<unsigned>(data.lifetimeBooks));
  const char* timeUnit = formatDuration(data.lifetimeSeconds, values[1], sizeof(values[1]));
  snprintf(values[2], sizeof(values[2]), "%lu", static_cast<unsigned long>(data.lifetimePages));
  const Card lifetime[] = {{tr(STR_STATS_BOOKS), values[0], nullptr},
                           {tr(STR_STATS_TIME), values[1], timeUnit},
                           {tr(STR_STATS_PAGES), values[2], nullptr}};
  drawCards(screen, fui::Rect{second.x, y, second.width, 0}, lifetime, 3);
}

void ReadingStatsPanel::drawUndated(UiAppHost::UiScreen& screen, const fui::Rect rect) {
  const auto& theme = screen.theme();
  int16_t y = rect.y;
  y = static_cast<int16_t>(y + drawSectionTitle(screen, rect, tr(STR_STATS_ALL_TIME), nullptr) + theme.spaceSm);
  const auto& data = snapshot.data();
  snprintf(values[0], sizeof(values[0]), "%u", static_cast<unsigned>(data.lifetimeBooks));
  const char* timeUnit = formatDuration(data.lifetimeSeconds, values[1], sizeof(values[1]));
  snprintf(values[2], sizeof(values[2]), "%lu", static_cast<unsigned long>(data.lifetimePages));
  const Card lifetime[] = {{tr(STR_STATS_BOOKS), values[0], nullptr},
                           {tr(STR_STATS_TIME), values[1], timeUnit},
                           {tr(STR_STATS_PAGES), values[2], nullptr}};
  y = static_cast<int16_t>(y + drawCards(screen, fui::Rect{rect.x, y, rect.width, 0}, lifetime, 3) + theme.spaceLg);

  auto hint = aligned(theme.smallText, fui::TextAlign::Center);
  hint.maxLines = 3;
  const int16_t hintHeight = static_cast<int16_t>(3 * screen.target().lineHeight(hint.font));
  if (rect.bottom() - y >= hintHeight) {
    screen.target().text(fui::Rect{rect.x, y, rect.width, hintHeight}, tr(STR_STATS_CLOCK_HINT), hint);
  }
}

void ReadingStatsPanel::drawPageDots(UiAppHost::UiScreen& screen, const fui::Rect rect, const int count,
                                     const int current) {
  const int16_t spacing = static_cast<int16_t>(DOT_SIZE * 2);
  const int16_t width = static_cast<int16_t>(count * DOT_SIZE + (count - 1) * (spacing - DOT_SIZE));
  int16_t x = static_cast<int16_t>(rect.x + (rect.width - width) / 2);
  const int16_t y = static_cast<int16_t>(rect.y + (rect.height - DOT_SIZE) / 2);
  const auto ink = fui::Paint::solid(fui::Color::Black);
  for (int i = 0; i < count; ++i) {
    const fui::Rect dot{x, y, DOT_SIZE, DOT_SIZE};
    if (i == current) {
      screen.target().fill(dot, ink, DOT_SIZE / 2);
    } else {
      screen.target().stroke(dot, ink, 1, DOT_SIZE / 2);
    }
    x = static_cast<int16_t>(x + spacing);
  }
}
