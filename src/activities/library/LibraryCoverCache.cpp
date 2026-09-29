#include "LibraryCoverCache.h"

#include <Bitmap.h>
#include <Epub.h>
#include <FsHelpers.h>
#include <GfxRenderer.h>
#include <HalStorage.h>
#include <I18n.h>
#include <Logging.h>
#include <Memory.h>
#include <Xtc.h>

#include "components/UITheme.h"
#include "components/UiAppHelpers.h"
#include "util/CoverCanvas.h"

namespace fui = freeink::ui;

namespace {
constexpr const char* CACHE_DIR = "/.crosspoint";
// Row buffers for decodeThumb() stay on the stack: list thumbs are generated
// at most COVER_WIDTH px wide, so these bounds leave margin for any depth.
constexpr int MAX_THUMB_WIDTH = 96;
constexpr int MAX_THUMB_ROW_BYTES = 96;

// Cache path of the book's thumb at list size; empty for formats without one.
// The constructors only derive paths: no parsing, no image work.
std::string thumbPathFor(const std::string& path) {
  if (FsHelpers::hasEpubExtension(path)) {
    auto epub = makeUniqueNoThrow<Epub>(path, CACHE_DIR);
    return epub ? epub->getThumbBmpPath(cover_canvas::SIZE) : std::string();
  }
  if (FsHelpers::hasXtcExtension(path)) {
    auto xtc = makeUniqueNoThrow<Xtc>(path, CACHE_DIR);
    return xtc ? xtc->getThumbBmpPath(cover_canvas::SIZE) : std::string();
  }
  return {};
}

bool generateThumb(const std::string& path) {
  // One parser at a time; both objects exceed the render task's stack budget.
  if (FsHelpers::hasEpubExtension(path)) {
    auto epub = makeUniqueNoThrow<Epub>(path, CACHE_DIR);
    return epub && epub->generateThumbBmpFromSource(cover_canvas::SIZE);
  }
  if (FsHelpers::hasXtcExtension(path)) {
    auto xtc = makeUniqueNoThrow<Xtc>(path, CACHE_DIR);
    return xtc && xtc->load() && xtc->generateThumbBmp(cover_canvas::SIZE);
  }
  return false;
}

fui::BitmapRef canvasBitmap(const uint8_t* canvas) {
  fui::BitmapRef ref;
  ref.data = canvas;
  ref.width = cover_canvas::SIZE;
  ref.height = cover_canvas::SIZE;
  ref.format = fui::BitmapFormat::BW1;
  ref.progmem = false;
  return ref;
}
}  // namespace

bool LibraryCoverCache::begin() {
  // Every slot plus the inverted copy for the selected row.
  pixels = makeUniqueNoThrow<uint8_t[]>(static_cast<size_t>(SLOT_COUNT + 1) * cover_canvas::BYTES);
  if (!pixels) {
    LOG_ERR("LIB", "OOM: cover canvases; showing icons");
    return false;
  }
  slots.fill(Slot{});
  triedCount = 0;
  triedNext = 0;
  buildStamp = 0;
  return true;
}

void LibraryCoverCache::end() {
  pixels.reset();
  slots.fill(Slot{});
  triedCount = 0;
  triedNext = 0;
}

uint8_t* LibraryCoverCache::canvasFor(const int slot) const {
  return pixels.get() + static_cast<size_t>(slot) * cover_canvas::BYTES;
}

uint8_t* LibraryCoverCache::invertedCanvas() const { return canvasFor(SLOT_COUNT); }

int LibraryCoverCache::findSlot(const uint64_t key) const {
  for (int i = 0; i < SLOT_COUNT; ++i) {
    if (slots[i].state != SlotState::Empty && slots[i].key == key) return i;
  }
  return -1;
}

int LibraryCoverCache::claimSlot() {
  int victim = -1;
  for (int i = 0; i < SLOT_COUNT; ++i) {
    if (slots[i].state == SlotState::Empty) return i;
    // Rows of the build in progress still point at their canvases.
    if (slots[i].lastUse == buildStamp) continue;
    if (victim < 0 || slots[i].lastUse < slots[victim].lastUse) victim = i;
  }
  return victim;
}

bool LibraryCoverCache::wasTried(const uint64_t key) const {
  for (int i = 0; i < triedCount; ++i) {
    if (tried[i] == key) return true;
  }
  return false;
}

void LibraryCoverCache::markTried(const uint64_t key) {
  tried[triedNext] = key;
  triedNext = static_cast<uint8_t>((triedNext + 1) % TRIED_COUNT);
  if (triedCount < TRIED_COUNT) ++triedCount;
}

fui::BitmapRef LibraryCoverCache::coverFor(const uint64_t key, const std::string& path, const bool inverted) {
  if (!pixels) return {};
  int slot = findSlot(key);
  if (slot < 0) {
    if (path.empty()) return {};
    slot = claimSlot();
    if (slot < 0) return {};
    slots[slot] = Slot{};
    slots[slot].key = key;
    slots[slot].path = path;
    load(slot);
  }
  slots[slot].lastUse = buildStamp;
  // Only real art needs flipping: the placeholder is line art like any icon.
  if (inverted && slots[slot].state == SlotState::Cover) {
    cover_canvas::invert(canvasFor(slot), invertedCanvas());
    return canvasBitmap(invertedCanvas());
  }
  return canvasBitmap(canvasFor(slot));
}

void LibraryCoverCache::load(const int slot) {
  auto& entry = slots[slot];
  uint8_t* canvas = canvasFor(slot);
  const std::string thumbPath = thumbPathFor(entry.path);
  if (thumbPath.empty()) {
    entry.state = SlotState::Placeholder;
  } else if (!Storage.exists(thumbPath.c_str())) {
    entry.state = SlotState::Missing;
  } else {
    // A cover that could not be decoded leaves an empty thumb behind as a
    // marker; it fails the header check here and keeps the placeholder.
    entry.state = decodeThumb(thumbPath, canvas) ? SlotState::Cover : SlotState::Placeholder;
  }
  if (entry.state != SlotState::Cover) drawPlaceholder(entry.path, canvas);
}

bool LibraryCoverCache::decodeThumb(const std::string& thumbPath, uint8_t* canvas) const {
  cover_canvas::clear(canvas);
  HalFile file;
  if (!Storage.openFileForRead("LIB", thumbPath, file)) return false;
  Bitmap bitmap(file);
  if (bitmap.parseHeaders() != BmpReaderError::Ok || bitmap.getWidth() <= 0 || bitmap.getHeight() <= 0 ||
      bitmap.rewindToData() != BmpReaderError::Ok) {
    return false;
  }
  const int width = bitmap.getWidth();
  const int height = bitmap.getHeight();
  if (width > MAX_THUMB_WIDTH || bitmap.getRowBytes() > MAX_THUMB_ROW_BYTES) {
    LOG_ERR("LIB", "cover thumb too wide (%d px): %s", width, thumbPath.c_str());
    return false;
  }
  // readNextRow() packs 2 bits per pixel: 0 black .. 3 white.
  uint8_t packed[(MAX_THUMB_WIDTH + 3) / 4];
  uint8_t raw[MAX_THUMB_ROW_BYTES];
  // Centered on the cover area; a thumb larger than it is cropped evenly.
  const int x0 = (cover_canvas::COVER_WIDTH - width) / 2;
  const int y0 = (cover_canvas::SIZE - height) / 2;
  for (int row = 0; row < height; ++row) {
    if (bitmap.readNextRow(packed, raw) != BmpReaderError::Ok) return false;
    const int y = y0 + (bitmap.isTopDown() ? row : height - 1 - row);
    if (y < 0 || y >= cover_canvas::SIZE) continue;
    for (int x = 0; x < width; ++x) {
      const int cx = x0 + x;
      if (cx < 0 || cx >= cover_canvas::COVER_WIDTH) continue;
      const uint8_t level = (packed[x / 4] >> (6 - 2 * (x % 4))) & 0x03;
      if (level < 2) cover_canvas::setInk(canvas, cx, y);
    }
  }
  cover_canvas::frame(canvas);
  return true;
}

void LibraryCoverCache::drawPlaceholder(const std::string& path, uint8_t* canvas) const {
  cover_canvas::clear(canvas);
  cover_canvas::frame(canvas);
  const fui::BitmapRef icon = listIconFor(UITheme::getFileIcon(path), 32);
  if (icon) {
    cover_canvas::blitCentered(canvas, icon.data, icon.width, icon.height, icon.format == fui::BitmapFormat::Mask1);
  }
}

bool LibraryCoverCache::generateMissing(const GfxRenderer& renderer) {
  if (!pixels) return false;
  int total = 0;
  for (const auto& slot : slots) {
    if (slot.state == SlotState::Missing && slot.lastUse == buildStamp && !wasTried(slot.key)) ++total;
  }
  if (total == 0) return false;

  const Rect popup = GUI.drawPopup(renderer, tr(STR_LOADING_POPUP));
  GUI.fillPopupProgress(renderer, popup, 0);
  int done = 0;
  for (int i = 0; i < SLOT_COUNT; ++i) {
    auto& slot = slots[i];
    if (slot.state != SlotState::Missing || slot.lastUse != buildStamp || wasTried(slot.key)) continue;
    // Tried once per visit: a book whose cover cannot be made must not bring
    // the popup back on every redraw.
    markTried(slot.key);
    if (!generateThumb(slot.path)) LOG_ERR("LIB", "no cover thumb for %s", slot.path.c_str());
    load(i);
    GUI.fillPopupProgress(renderer, popup, ++done * 100 / total);
  }
  return true;
}
