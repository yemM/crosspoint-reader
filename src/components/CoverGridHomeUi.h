#pragma once

#include "HomeShellUi.h"

// Home with the recent books as covers: the hero card, then a grid.
class CoverGridHomeUi final : public HomeShellUi {
 public:
  using HomeShellUi::HomeShellUi;
  int maxBooks() const override { return GRID_MAX_BOOKS; }

 private:
  void drawBody(UiScreen& screen, freeink::ui::Rect rect) override { drawCoverGrid(screen, rect); }
};
