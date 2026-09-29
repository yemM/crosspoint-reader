#pragma once

#include <FreeInkUICore.h>

#include <array>
#include <cstdint>
#include <memory>
#include <string>

#include "util/CoverSlots.h"

class GfxRenderer;

// Library-row covers, decoded from each book's cached thumb BMP into the
// square icon canvas fui::list draws (see util/CoverCanvas.h).
//
// Lives for one visit to the Library screen. Slots are keyed by the book's
// path hash (library::clixPathHash, the index's own key) and managed by
// CoverSlotTable, so scrolling back to a page costs no SD reads and every
// ListItem of one list() pass keeps valid pixels.
//
// Thumbs that do not exist yet are not generated while the list is being
// built, since that decodes the cover JPEG/PNG. The row shows a placeholder,
// and generateMissing() makes the page's missing thumbs once the list is on
// screen, behind a progress popup. Refresh library can make them all ahead of
// time through generateFor().
class LibraryCoverCache {
 public:
  // One fallible allocation for every canvas; false leaves covers off and the
  // caller keeps its file-type icons.
  bool begin();
  void end();
  bool ready() const { return pixels != nullptr; }

  // Call once per list build, before the first coverFor().
  void beginBuild() { table.beginBuild(); }
  // Whether the book already has a slot. Callers resolve the book's path (a
  // folder walk in the index) only when it does not.
  bool contains(uint64_t key) const { return table.find(key) >= 0; }
  // The row icon for this book. path is only read when the key has no slot
  // yet. inverted is for rows whose icon is drawn in white (the selected row
  // on invert-fill themes). Empty only when every slot is already in use by
  // this build.
  freeink::ui::BitmapRef coverFor(uint64_t key, const std::string& path, bool inverted);
  // Generates the thumbs the last build found missing, each book tried once
  // per visit. True when it drew its popup, so the caller must redraw.
  bool generateMissing(const GfxRenderer& renderer);

  // Whether the book can have a list thumb and has none yet.
  static bool thumbMissing(const std::string& path);
  // Generates one book's list thumb now and counts it as tried for this visit.
  // The book's slot, if any, reloads on its next build.
  void generateFor(uint64_t key, const std::string& path);

 private:
  static constexpr int SLOT_COUNT = 16;
  // Books whose thumb generation already ran this visit, kept apart from the
  // slots so an evicted book does not bring the popup back when scrolled to
  // again.
  static constexpr int TRIED_COUNT = 32;

  enum class SlotState : uint8_t { Cover, Placeholder, Missing };
  struct SlotData {
    std::string path;
    SlotState state = SlotState::Placeholder;
  };

  uint8_t* canvasFor(int slot) const;
  uint8_t* invertedCanvas() const;
  // Decodes the book's thumb into the slot's canvas, or draws the placeholder
  // when there is none (yet).
  void load(int slot);
  bool decodeThumb(const std::string& thumbPath, uint8_t* canvas) const;
  void drawPlaceholder(const std::string& path, uint8_t* canvas) const;

  std::unique_ptr<uint8_t[]> pixels;
  CoverSlotTable<SLOT_COUNT> table;
  std::array<SlotData, SLOT_COUNT> data;
  CoverKeyRing<TRIED_COUNT> tried;
};
