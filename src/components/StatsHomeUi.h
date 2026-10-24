#pragma once

#include "HomeShellUi.h"
#include "ReadingStatsPanel.h"

// Cover Grid home with reading statistics one swipe away: page 0 is the grid
// of recent covers, the next pages are the statistics panel's.
class StatsHomeUi final : public HomeShellUi {
 public:
  using HomeShellUi::HomeShellUi;
  int maxBooks() const override { return GRID_MAX_BOOKS; }

  // True once after the statistics were tapped (they ask for the next page).
  bool takePageTap();
  // Moves by dir pages, wrapping around.
  void flipPage(int dir);
  bool showsGrid() const { return page == 0; }

 private:
  static constexpr freeink::ui::ActionId STATS_PAGE = 2;

  static void onPageAction(const freeink::ui::ActionEvent& event, void* user);
  int pageCount() const { return 1 + panel.pageCount(); }
  void onBegin() override;
  void drawBody(UiScreen& screen, freeink::ui::Rect rect) override;
  void drawNoBooks(UiScreen& screen, freeink::ui::Rect rect) override;
  int16_t footerHeight() const override { return ReadingStatsPanel::PAGE_DOTS_HEIGHT; }
  void drawFooter(UiScreen& screen, freeink::ui::Rect rect) override;
  void drawPanel(UiScreen& screen, freeink::ui::Rect rect);

  ReadingStatsPanel panel;
  int page = 0;
  bool pageTapped = false;
};
