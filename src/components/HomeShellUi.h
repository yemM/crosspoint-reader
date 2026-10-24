#pragma once

#include <array>
#include <string>
#include <vector>

#include "HomeCoverCache.h"
#include "RecentBooksStore.h"
#include "UiAppHost.h"
#include "components/bars/tab-bar.h"
#include "components/media/book-card.h"
#include "components/media/cover-grid.h"

// Home screen chrome shared by the Cover Grid and Stats homes: the status
// band, the "continue reading" hero card and the bottom tab bar. Subclasses
// fill the area between the hero card and the tabs, optionally above a footer
// strip, and can draw the grid of recent covers there.
//
// Selection values are flat, as HomeActivity counts them: books first (the
// hero is 0), then the tab items.
class HomeShellUi : public UiAppHost {
 public:
  static constexpr int THUMB_HEIGHT = 400;
  static constexpr int GRID_COLUMNS = 3;
  static constexpr int GRID_ROWS = 2;
  // The hero plus a full grid.
  static constexpr int GRID_MAX_BOOKS = 1 + GRID_COLUMNS * GRID_ROWS;
  static_assert(GRID_MAX_BOOKS <= HomeCoverCache::MAX_COVERS);

  explicit HomeShellUi(GfxRenderer& renderer);
  virtual ~HomeShellUi() = default;

  // Recent books this home shows, the hero first.
  virtual int maxBooks() const = 0;

  void begin(const std::vector<RecentBook>& books, bool hasOpds, bool hasContinueReading);
  void refreshCoverPaths();
  void setSelection(int selection) { selected = selection; }
  int selectedAction(const MappedInputManager& input);
  // Exact generation height, shared by every slot and recorded during draw.
  // Thumbs must be generated at the drawn size: rescaling a dithered 1-bit
  // image aliases badly.
  int thumbHeightFor() const;
  bool takeThumbHeightChanged();

 protected:
  static constexpr freeink::ui::ActionId SELECT = 1;
  // Grid cell padding around each cover; also feeds the screen's horizontal
  // inset so the cover columns land on the header chrome's inset line.
  static constexpr int16_t COVER_CELL_INSET = 6;
  // Registers subclass actions; runs in begin() after the SELECT action.
  virtual void onBegin() {}
  // The area below the hero card, above the tabs.
  virtual void drawBody(UiScreen& screen, freeink::ui::Rect rect) = 0;
  // The whole body when there is no book to continue.
  virtual void drawNoBooks(UiScreen& screen, freeink::ui::Rect rect);
  // Height of a strip kept between the body and the tabs; 0 for none.
  virtual int16_t footerHeight() const { return 0; }
  virtual void drawFooter(UiScreen&, freeink::ui::Rect) {}

  // The recent books after the hero, as a grid of covers.
  void drawCoverGrid(UiScreen& screen, freeink::ui::Rect rect);

  bool paintFramedCover(freeink::ui::DrawTarget& target, freeink::ui::Rect rect, size_t index);

  GfxRenderer& renderer;
  const std::vector<RecentBook>* books = nullptr;
  int selected = 0;
  // Gap between cover rows.
  int rowGap = 4;
  // Hero card style and cover size, shared with the grid covers.
  freeink::ui::BookCardProps card;

 private:
  static void screenFn(UiScreen& screen, void* user);
  static void onAction(const freeink::ui::ActionEvent& event, void* user);
  void draw(UiScreen& screen);
  void drawHeaderBand();
  void drawEmpty(UiScreen& screen, freeink::ui::Rect rect);
  void drawCurrent(UiScreen& screen, freeink::ui::Rect rect, int coverRowHeight);
  void drawTabs(UiScreen& screen, freeink::ui::Rect rect);
  freeink::ui::Rect layoutGrid(freeink::ui::Rect rect);
  void refreshCoverPath(size_t index);
  void noteThumbHeight(int slotHeight);

  HomeCoverCache coverCache;
  std::array<std::string, HomeCoverCache::MAX_COVERS> coverPaths;
  int thumbHeight = 0;
  bool thumbHeightChanged = false;
  int pending = -1;
  int progress = -1;
  bool hasOpds = false;
  bool hasContinueReading = false;
  char progressText[12]{};
  // Component styles and interaction tables stay off the render task's stack.
  freeink::ui::CoverGridProps grid;
  freeink::ui::TabBarProps tabs;
  std::array<freeink::ui::TabItem, 5> tabItems;
};
