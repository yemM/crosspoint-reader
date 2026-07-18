#include "FlatBookList.h"

#include <Epub.h>
#include <FsHelpers.h>
#include <GfxRenderer.h>
#include <HalStorage.h>
#include <I18n.h>
#include <Logging.h>
#include <Xtc.h>

#include <algorithm>
#include <cstring>
#include <functional>
#include <new>

#include "MappedInputManager.h"
#include "components/UITheme.h"

namespace {
constexpr const char* kCacheDir = "/.crosspoint";

std::string basenameOf(const std::string& path) {
  const auto pos = path.find_last_of('/');
  return pos == std::string::npos ? path : path.substr(pos + 1);
}

std::string titleFallback(const std::string& path) {
  std::string name = basenameOf(path);
  const auto dot = name.find_last_of('.');
  return dot == std::string::npos ? name : name.substr(0, dot);
}

// Resolves an epub's metadata (cheap cache read first, full build behind showPopup() on a miss)
// and, if requested, its cover thumbnail at wantThumbHeight. A single Epub instance is used
// throughout because Epub::generateThumbBmp requires the metadata cache to already be loaded on
// that same instance.
void resolveEpub(FlatBookList::Entry& entry, int wantThumbHeight, const std::function<void()>& showPopup) {
  Epub epub(entry.path, kCacheDir);
  bool loaded = epub.load(/*buildIfMissing=*/false, /*skipLoadingCss=*/true);
  if (!loaded) {
    showPopup();
    loaded = epub.load(/*buildIfMissing=*/true, /*skipLoadingCss=*/true);
  }

  if (loaded) {
    entry.title = epub.getTitle().empty() ? titleFallback(entry.path) : epub.getTitle();
    entry.author = epub.getAuthor();
    entry.meta = FlatBookList::Meta::Loaded;
  } else {
    entry.meta = FlatBookList::Meta::None;
  }

  if (wantThumbHeight == 0) {
    return;  // Thumb resolution deferred until a thumbnail style (Covers/Grid) actually needs it.
  }
  if (entry.meta != FlatBookList::Meta::Loaded) {
    return;  // No metadata means no cover; nothing to resolve regardless of requested height.
  }

  const std::string thumbPath = epub.getThumbBmpPath(wantThumbHeight);
  if (!Storage.exists(thumbPath.c_str())) {
    showPopup();
  }
  entry.thumbPath = epub.generateThumbBmp(wantThumbHeight) ? thumbPath : "";
  entry.thumbHeightResolved = wantThumbHeight;
}

// Xtc has no cheap/full split (XtcParser::open is a lightweight container open, not a multi-pass
// index build), so metadata never needs the popup — only thumbnail generation (image decode) does.
void resolveXtc(FlatBookList::Entry& entry, int wantThumbHeight, const std::function<void()>& showPopup) {
  Xtc xtc(entry.path, kCacheDir);
  if (!xtc.load()) {
    entry.meta = FlatBookList::Meta::None;
    return;
  }

  entry.title = xtc.getTitle().empty() ? titleFallback(entry.path) : xtc.getTitle();
  entry.author = xtc.getAuthor();
  entry.meta = FlatBookList::Meta::Loaded;

  if (wantThumbHeight == 0) {
    return;
  }

  const std::string thumbPath = xtc.getThumbBmpPath(wantThumbHeight);
  if (!Storage.exists(thumbPath.c_str())) {
    showPopup();
  }
  entry.thumbPath = xtc.generateThumbBmp(wantThumbHeight) ? thumbPath : "";
  entry.thumbHeightResolved = wantThumbHeight;
}

// txt/md have no embedded metadata or cover; displayTitle() falls back to the filename.
void resolveTextLike(FlatBookList::Entry& entry) { entry.meta = FlatBookList::Meta::None; }

// A wide/deep folder tree is user-reachable (no malicious input needed) and would otherwise grow
// dirStack without bound: every subdirectory found is pushed before any of its siblings are popped
// (DFS via a LIFO stack), so a single directory with thousands of children pushes them all at once.
// Bounding it lets us reserve its capacity exactly once, the same way MAX_BOOKS bounds entries.
// Kept small (192, ~4.6KB) rather than matching MAX_BOOKS: this reserve is held concurrently with
// entries.reserve(MAX_BOOKS) (~31KB for sizeof(Entry)==104), so an oversized cap here would spend
// scarce heap guarding an allocation path instead of shrinking its OOM risk. 192 is sized off the
// layout that actually reaches this cap: DFS pushes every child of a directory before descending
// into any of them, so a Calibre-style /Books/<author>/ library with ~100 author folders holding
// 2 books each stacks ~100 directories while staying well under MAX_BOOKS. A tighter cap would
// silently skip those authors and present a partial list as complete.
constexpr size_t MAX_DIR_STACK = 192;

// Probes a same-sized allocation through the nothrow global operator new and immediately frees it.
// vector::reserve() allocates through the THROWING global operator new; under -fno-exceptions
// (CLAUDE.md rule 9) a failed throwing new calls abort(), not a recoverable failure. This probe
// narrows the failure window to the handful of instructions between the ::operator delete below
// and the caller's reserve() call — it is not a guarantee under preemption: this is a single-core
// RTOS running a preemptive scheduler alongside WiFi/lwIP/WebServer/mDNS, and a tick interrupt
// landing in that window could schedule another allocating context, which is exactly the scenario
// most likely under the memory pressure this guard exists for. It is a documented mitigation that
// makes the common case observable and recoverable, not an invariant that can never fail.
bool canAllocate(size_t bytes) {
  void* probe = ::operator new(bytes, std::nothrow);
  if (!probe) return false;
  ::operator delete(probe);
  return true;
}
}  // namespace

bool FlatBookList::scan(char* nameBuffer, size_t bufferSize) {
  entries.clear();
  // MAX_BOOKS is the retune knob. See canAllocate() above for why probing first makes this
  // reserve() non-aborting rather than merely less likely to abort.
  const size_t entriesBytes = MAX_BOOKS * sizeof(Entry);
  if (!canAllocate(entriesBytes)) {
    LOG_ERR("FBL", "OOM: cannot reserve %zu bytes for %zu book entries", entriesBytes, MAX_BOOKS);
    return false;
  }
  entries.reserve(MAX_BOOKS);

  if (!nameBuffer) {
    LOG_ERR("FBL", "nameBuffer not allocated");
    return false;
  }

  std::vector<std::string> dirStack;
  // Reserved once at its hard cap (MAX_DIR_STACK) and never grown past it (see the push loop
  // below), so — like entries above — this can only ever satisfy this single reserve() call.
  const size_t dirStackBytes = MAX_DIR_STACK * sizeof(std::string);
  if (!canAllocate(dirStackBytes)) {
    LOG_ERR("FBL", "OOM: cannot reserve %zu bytes for directory stack", dirStackBytes);
    // entries.reserve(MAX_BOOKS) above already succeeded, so entries.clear() alone would leave its
    // ~31KB reserved-but-empty for the rest of the activity — exactly when the heap is already
    // under pressure. swap() with a temporary is guaranteed non-allocating (unlike shrink_to_fit(),
    // which is only a non-binding request) and actually releases the capacity.
    std::vector<Entry>().swap(entries);
    return false;
  }
  dirStack.reserve(MAX_DIR_STACK);
  dirStack.push_back("/");

  bool capped = false;
  bool dirStackCapped = false;
  while (!dirStack.empty() && !capped) {
    const std::string currentPath = std::move(dirStack.back());
    dirStack.pop_back();

    auto dir = Storage.open(currentPath.c_str());
    if (!dir || !dir.isDirectory()) {
      continue;
    }
    dir.rewindDirectory();

    for (auto file = dir.openNextFile(); file; file = dir.openNextFile()) {
      file.getName(nameBuffer, bufferSize);
      if (strcmp(nameBuffer, ".") == 0 || strcmp(nameBuffer, "..") == 0) {
        continue;
      }
      // Dot-entries (including ".crosspoint") and the Windows recycle-bin marker are always
      // skipped here, regardless of SETTINGS.showHiddenFiles — this is a book index, not a
      // file manager listing.
      if (nameBuffer[0] == '.' || strcmp(nameBuffer, "System Volume Information") == 0) {
        continue;
      }

      std::string entryPath = currentPath;
      if (entryPath.back() != '/') entryPath += "/";
      entryPath += nameBuffer;

      if (file.isDirectory()) {
        if (dirStack.size() >= MAX_DIR_STACK) {
          if (!dirStackCapped) {
            dirStackCapped = true;
            LOG_ERR("FBL", "All-books scan: directory stack capped at %zu, some folders skipped", MAX_DIR_STACK);
          }
          continue;
        }
        dirStack.push_back(std::move(entryPath));
        continue;
      }

      const std::string_view nameView{nameBuffer};
      if (!FsHelpers::hasEpubExtension(nameView) && !FsHelpers::hasXtcExtension(nameView) &&
          !FsHelpers::hasTxtExtension(nameView) && !FsHelpers::hasMarkdownExtension(nameView)) {
        continue;
      }

      if (entries.size() >= MAX_BOOKS) {
        capped = true;
        break;
      }

      Entry entry;
      entry.path = std::move(entryPath);
      entries.push_back(std::move(entry));
    }
  }

  if (capped) {
    LOG_INF("FBL", "All-books scan capped at %zu entries (subset in walk order)", MAX_BOOKS);
  }

  std::sort(entries.begin(), entries.end(), [](const Entry& a, const Entry& b) {
    return FsHelpers::naturalLess(basenameOf(a.path), basenameOf(b.path));
  });

  return true;
}

bool FlatBookList::pageNeedsWork(size_t start, size_t count, int wantThumbHeight) const {
  const size_t end = std::min(start + count, entries.size());
  for (size_t i = start; i < end; i++) {
    const Entry& entry = entries[i];
    if (entry.meta == Meta::Unknown) return true;
    if (wantThumbHeight != 0 && entry.meta == Meta::Loaded && entry.thumbHeightResolved != wantThumbHeight) {
      return true;
    }
  }
  return false;
}

bool FlatBookList::ensureVisibleMetadata(GfxRenderer& renderer, MappedInputManager& mappedInput, size_t start,
                                         size_t count, int wantThumbHeight, bool& aborted) {
  aborted = false;
  bool changed = false;
  bool showingPopup = false;
  Rect popupRect;

  const size_t end = std::min(start + count, entries.size());
  const size_t total = end > start ? end - start : 1;
  size_t progress = 0;

  auto showPopup = [&] {
    if (!showingPopup) {
      showingPopup = true;
      popupRect = GUI.drawPopup(renderer, tr(STR_INDEXING_BOOKS));
    }
    GUI.fillPopupProgress(renderer, popupRect, static_cast<int>(10 + progress * 90 / total));
  };

  for (size_t i = start; i < end; i++) {
    Entry& entry = entries[i];
    const bool needsMeta = entry.meta == Meta::Unknown;
    const bool needsThumb =
        wantThumbHeight != 0 && entry.meta == Meta::Loaded && entry.thumbHeightResolved != wantThumbHeight;
    if (!needsMeta && !needsThumb) {
      continue;
    }

    // Poll input between books so a long Back press can abort the remainder of the page instead
    // of forcing the user to wait out a long run of uncached books.
    mappedInput.update();
    if (mappedInput.isPressed(MappedInputManager::Button::Back)) {
      aborted = true;
      break;
    }

    if (FsHelpers::hasEpubExtension(entry.path)) {
      resolveEpub(entry, wantThumbHeight, showPopup);
    } else if (FsHelpers::hasXtcExtension(entry.path)) {
      resolveXtc(entry, wantThumbHeight, showPopup);
    } else {
      resolveTextLike(entry);
    }
    changed = true;
    progress++;
  }

  return changed;
}

void FlatBookList::removeAt(size_t index) {
  if (index >= entries.size()) return;
  entries.erase(entries.begin() + static_cast<std::ptrdiff_t>(index));
}

std::string FlatBookList::displayTitle(const Entry& entry) {
  return entry.title.empty() ? titleFallback(entry.path) : entry.title;
}
