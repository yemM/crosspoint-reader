#include "StatsHomeUi.h"

#include <utility>

#include "fontIds.h"

namespace fui = freeink::ui;

void StatsHomeUi::onBegin() {
  // The card values are the panel's headline figures: the title slot takes the
  // large sans (the hero card, grid and tabs do not use it).
  uiTarget.setFont(fui::GfxRendererTarget::FONT_TITLE, NOTOSANS_18_FONT_ID);
  app.on(STATS_PAGE, &StatsHomeUi::onPageAction, this);
  panel.begin();
  page = 0;
}

void StatsHomeUi::onPageAction(const fui::ActionEvent&, void* user) {
  auto& self = *static_cast<StatsHomeUi*>(user);
  self.pageTapped = true;
  self.app.clearTapFlash();
}

bool StatsHomeUi::takePageTap() { return std::exchange(pageTapped, false); }

void StatsHomeUi::flipPage(const int dir) {
  const int count = pageCount();
  page = ((page + dir) % count + count) % count;
  if (page > 0) panel.setPage(page - 1);
}

void StatsHomeUi::drawBody(UiScreen& screen, const fui::Rect rect) {
  if (showsGrid()) {
    drawCoverGrid(screen, rect);
  } else {
    drawPanel(screen, rect);
  }
}

void StatsHomeUi::drawNoBooks(UiScreen& screen, const fui::Rect rect) {
  if (showsGrid()) {
    HomeShellUi::drawNoBooks(screen, rect);
  } else {
    drawPanel(screen, rect);
  }
}

void StatsHomeUi::drawFooter(UiScreen& screen, const fui::Rect rect) {
  ReadingStatsPanel::drawPageDots(screen, rect, pageCount(), page);
}

void StatsHomeUi::drawPanel(UiScreen& screen, const fui::Rect rect) {
  // Same side inset as the tab bar below, so the panel lines up with it.
  panel.draw(screen, rect.inset(fui::Insets{0, COVER_CELL_INSET, 0, COVER_CELL_INSET}), STATS_PAGE);
}
