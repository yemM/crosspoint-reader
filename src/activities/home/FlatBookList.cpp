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

#include "MappedInputManager.h"
#include "components/UITheme.h"
#include "components/themes/BaseTheme.h"

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
// and, if requested, its cover thumbnail. A single Epub instance is used throughout because
// Epub::generateThumbBmp requires the metadata cache to already be loaded on that same instance.
void resolveEpub(FlatBookList::Entry& entry, bool wantThumbs, const std::function<void()>& showPopup) {
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

  if (!wantThumbs) {
    return;  // Thumb resolution deferred until Covers style actually needs it.
  }
  if (entry.meta != FlatBookList::Meta::Loaded) {
    entry.thumbResolved = true;
    return;
  }

  const std::string thumbPath = epub.getThumbBmpPath(BaseTheme::bookListThumbHeight);
  if (!Storage.exists(thumbPath.c_str())) {
    showPopup();
  }
  entry.thumbPath = epub.generateThumbBmp(BaseTheme::bookListThumbHeight) ? thumbPath : "";
  entry.thumbResolved = true;
}

// Xtc has no cheap/full split (XtcParser::open is a lightweight container open, not a multi-pass
// index build), so metadata never needs the popup — only thumbnail generation (image decode) does.
void resolveXtc(FlatBookList::Entry& entry, bool wantThumbs, const std::function<void()>& showPopup) {
  Xtc xtc(entry.path, kCacheDir);
  if (!xtc.load()) {
    entry.meta = FlatBookList::Meta::None;
    entry.thumbResolved = true;
    return;
  }

  entry.title = xtc.getTitle().empty() ? titleFallback(entry.path) : xtc.getTitle();
  entry.author = xtc.getAuthor();
  entry.meta = FlatBookList::Meta::Loaded;

  if (!wantThumbs) {
    return;
  }

  const std::string thumbPath = xtc.getThumbBmpPath(BaseTheme::bookListThumbHeight);
  if (!Storage.exists(thumbPath.c_str())) {
    showPopup();
  }
  entry.thumbPath = xtc.generateThumbBmp(BaseTheme::bookListThumbHeight) ? thumbPath : "";
  entry.thumbResolved = true;
}

// txt/md have no embedded metadata or cover; displayTitle() falls back to the filename.
void resolveTextLike(FlatBookList::Entry& entry) {
  entry.meta = FlatBookList::Meta::None;
  entry.thumbResolved = true;
}
}  // namespace

bool FlatBookList::scan(char* nameBuffer, size_t bufferSize) {
  entries.clear();
  // Single ~30KB block; vector's throwing operator new aborts on OOM. Acceptable here:
  // the browser context has no reader buffers live. MAX_BOOKS is the retune knob.
  entries.reserve(MAX_BOOKS);

  if (!nameBuffer) {
    LOG_ERR("FBL", "nameBuffer not allocated");
    return false;
  }

  std::vector<std::string> dirStack;
  dirStack.reserve(16);
  dirStack.push_back("/");

  bool capped = false;
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

bool FlatBookList::pageNeedsWork(size_t start, size_t count, bool wantThumbs) const {
  const size_t end = std::min(start + count, entries.size());
  for (size_t i = start; i < end; i++) {
    const Entry& entry = entries[i];
    if (entry.meta == Meta::Unknown) return true;
    if (wantThumbs && entry.meta == Meta::Loaded && !entry.thumbResolved) return true;
  }
  return false;
}

bool FlatBookList::ensureVisibleMetadata(GfxRenderer& renderer, MappedInputManager& mappedInput, size_t start,
                                         size_t count, bool wantThumbs, bool& aborted) {
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
    const bool needsThumb = wantThumbs && entry.meta == Meta::Loaded && !entry.thumbResolved;
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
      resolveEpub(entry, wantThumbs, showPopup);
    } else if (FsHelpers::hasXtcExtension(entry.path)) {
      resolveXtc(entry, wantThumbs, showPopup);
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
