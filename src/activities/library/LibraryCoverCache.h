#pragma once

#include <FreeInkUICore.h>

#include <array>
#include <cstdint>
#include <memory>
#include <string>

class GfxRenderer;

// Library-row covers, decoded from each book's cached thumb BMP into the
// square icon canvas fui::list draws (see util/CoverCanvas.h).
//
// Lives for one visit to the Library screen. Slots are keyed by the book's
// path hash (library::clixPathHash, the index's own key) and reused
// least-recently-used first, so scrolling back to a page costs no SD reads. A
// slot handed out during a build is never recycled within that same build:
// every ListItem of one list() pass keeps valid pixels.
//
// Thumbs that do not exist yet are not generated while the list is being
// built, since that decodes the cover JPEG/PNG. The row shows a placeholder,
// and generateMissing() makes the page's missing thumbs once the list is on
// screen, behind a progress popup.
class LibraryCoverCache {
 public:
  // One fallible allocation for every canvas; false leaves covers off and the
  // caller keeps its file-type icons.
  bool begin();
  void end();
  bool ready() const { return pixels != nullptr; }

  // Call once per list build, before the first coverFor().
  void beginBuild() { ++buildStamp; }
  // Whether the book already has a slot. Callers resolve the book's path (a
  // folder walk in the index) only when it does not.
  bool contains(uint64_t key) const { return findSlot(key) >= 0; }
  // The row icon for this book. path is only read when the key has no slot
  // yet. inverted is for rows whose icon is drawn in white (the selected row
  // on invert-fill themes). Empty only when every slot is already in use by
  // this build.
  freeink::ui::BitmapRef coverFor(uint64_t key, const std::string& path, bool inverted);
  // Generates the thumbs the last build found missing, each book tried once
  // per visit. True when it drew its popup, so the caller must redraw.
  bool generateMissing(const GfxRenderer& renderer);

 private:
  static constexpr int SLOT_COUNT = 16;
  // Books whose thumb generation already ran this visit, kept apart from the
  // slots so an evicted book does not bring the popup back when scrolled to
  // again. Oldest entries are overwritten first.
  static constexpr int TRIED_COUNT = 32;

  enum class SlotState : uint8_t { Empty, Cover, Placeholder, Missing };
  struct Slot {
    uint64_t key = 0;
    std::string path;
    uint32_t lastUse = 0;
    SlotState state = SlotState::Empty;
  };

  uint8_t* canvasFor(int slot) const;
  uint8_t* invertedCanvas() const;
  int findSlot(uint64_t key) const;
  int claimSlot();
  bool wasTried(uint64_t key) const;
  void markTried(uint64_t key);
  // Decodes the book's thumb into the slot's canvas, or draws the placeholder
  // when there is none (yet).
  void load(int slot);
  bool decodeThumb(const std::string& thumbPath, uint8_t* canvas) const;
  void drawPlaceholder(const std::string& path, uint8_t* canvas) const;

  std::unique_ptr<uint8_t[]> pixels;
  std::array<Slot, SLOT_COUNT> slots;
  std::array<uint64_t, TRIED_COUNT> tried{};
  uint8_t triedCount = 0;
  uint8_t triedNext = 0;
  uint32_t buildStamp = 0;
};
