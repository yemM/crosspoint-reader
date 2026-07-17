#include "FileBrowserActivity.h"

#include <FsHelpers.h>
#include <GfxRenderer.h>
#include <HalStorage.h>
#include <I18n.h>
#include <Memory.h>

#include <algorithm>

#include "CrossPointSettings.h"
#include "MappedInputManager.h"
#include "activities/util/ConfirmationActivity.h"
#include "components/UITheme.h"
#include "components/themes/BaseTheme.h"
#include "fontIds.h"
#include "util/BookCacheUtils.h"

namespace {
constexpr unsigned long GO_HOME_MS = 1000;
constexpr size_t NAME_BUFFER_SIZE = 500;

std::string basenameOf(const std::string& path) {
  const auto pos = path.find_last_of('/');
  return pos == std::string::npos ? path : path.substr(pos + 1);
}
}  // namespace

void FileBrowserActivity::loadFiles() {
  files.clear();

  auto root = Storage.open(basepath.c_str());
  if (!root || !root.isDirectory()) {
    return;
  }

  root.rewindDirectory();

  if (!fileNameBuffer) {
    LOG_ERR("FileBrowser", "fileNameBuffer not allocated");
    root.close();
    return;
  }

  for (auto file = root.openNextFile(); file; file = root.openNextFile()) {
    file.getName(fileNameBuffer.get(), NAME_BUFFER_SIZE);
    if ((!SETTINGS.showHiddenFiles && fileNameBuffer[0] == '.') ||
        strcmp(fileNameBuffer.get(), "System Volume Information") == 0) {
      continue;
    }

    if (file.isDirectory()) {
      files.emplace_back(std::string(fileNameBuffer.get()) + "/");
    } else {
      std::string_view filename{fileNameBuffer.get()};
      if (mode == Mode::PickFirmware) {
        // Firmware picker: only show .bin files.
        if (FsHelpers::checkFileExtension(filename, ".bin")) {
          files.emplace_back(filename);
        }
      } else if (FsHelpers::hasEpubExtension(filename) || FsHelpers::hasXtcExtension(filename) ||
                 FsHelpers::hasTxtExtension(filename) || FsHelpers::hasMarkdownExtension(filename) ||
                 FsHelpers::hasBmpExtension(filename)) {
        files.emplace_back(filename);
      }
    }
  }
  root.close();
  FsHelpers::sortFileList(files);
}

void FileBrowserActivity::onEnter() {
  Activity::onEnter();

  fileNameBuffer = makeUniqueNoThrow<char[]>(NAME_BUFFER_SIZE);
  if (!fileNameBuffer) {
    LOG_ERR("FileBrowser", "malloc failed for name buffer");
    return;
  }

  selectorIndex = 0;
  indexAbortedPage = SIZE_MAX;
  lockNextBackRelease = false;

  // If Confirm was held while this activity opened (typical when launched from a menu), ignore
  // its release — otherwise we'd immediately auto-open whatever is at index 0.
  lockNextConfirmRelease = mappedInput.isPressed(MappedInputManager::Button::Confirm);

  if (mode == Mode::Books && SETTINGS.browserFlatView) {
    // Flat view takes priority over any preselected file path — see FileBrowserActivity.h.
    enterAllBooksView(/*forceScan=*/true);
    requestUpdate();
    return;
  }

  auto root = Storage.open(basepath.c_str());
  if (!root) {
    basepath = "/";
    loadFiles();
  } else if (!root.isDirectory()) {
    lockLongPressBack = mappedInput.isPressed(MappedInputManager::Button::Back);

    const std::string oldPath = basepath;
    basepath = FsHelpers::extractFolderPath(basepath);
    loadFiles();

    const auto pos = oldPath.find_last_of('/');
    const std::string fileName = oldPath.substr(pos + 1);
    selectorIndex = findEntry(fileName) + (hasTabBar() ? 1 : 0);
  } else {
    loadFiles();
  }

  requestUpdate();
}

void FileBrowserActivity::onExit() {
  Activity::onExit();
  files.clear();
  fileNameBuffer.reset();
  flatBooks.reset();
  flatScanned = false;
}

bool FileBrowserActivity::inAllBooksView() const {
  return hasTabBar() && SETTINGS.browserFlatView && flatBooks != nullptr;
}

size_t FileBrowserActivity::itemCount() const { return inAllBooksView() ? flatBooks->size() : files.size(); }

int FileBrowserActivity::getPageItems() const {
  const auto& metrics = UITheme::getInstance().getMetrics();
  const int pathReserved = renderer.getLineHeight(SMALL_FONT_ID) + metrics.verticalSpacing;
  const int contentTop = metrics.topPadding + metrics.headerHeight + (hasTabBar() ? metrics.tabBarHeight : 0);
  const int contentHeight =
      renderer.getScreenHeight() - contentTop - metrics.buttonHintsHeight - metrics.verticalSpacing - pathReserved;

  if (inAllBooksView() && SETTINGS.allBooksViewStyle == CrossPointSettings::ALL_BOOKS_COVERS) {
    return std::max(1, contentHeight / GUI.getBookListRowHeight());
  }
  const int rowHeight = inAllBooksView() ? metrics.listWithSubtitleRowHeight : metrics.listRowHeight;
  return std::max(1, contentHeight / rowHeight);
}

void FileBrowserActivity::toggleViewMode() {
  SETTINGS.browserFlatView = !SETTINGS.browserFlatView;
  SETTINGS.saveToFile();
  indexAbortedPage = SIZE_MAX;

  if (SETTINGS.browserFlatView) {
    enterAllBooksView(/*forceScan=*/false);
  } else {
    basepath = "/";
    loadFiles();
  }
  // selectorIndex stays on the tab-bar slot (0) either way, mirroring SettingsActivity's
  // category tab, which keeps its own slot 0 selected across category switches.
}

void FileBrowserActivity::enterAllBooksView(bool forceScan) {
  if (!flatBooks) {
    flatBooks = makeUniqueNoThrow<FlatBookList>();
  }
  if (!flatBooks) {
    LOG_ERR("FileBrowser", "OOM allocating FlatBookList; falling back to folder view");
    SETTINGS.browserFlatView = 0;
    SETTINGS.saveToFile();
    basepath = "/";
    loadFiles();
    return;
  }

  if (forceScan || !flatScanned) {
    GUI.drawPopup(renderer, tr(STR_SCANNING_BOOKS));
    flatScanned = flatBooks->scan(fileNameBuffer.get(), NAME_BUFFER_SIZE);
  }
  indexAbortedPage = SIZE_MAX;
}

// To avoid traversing directories twice (once for cache clearing, once for deletion),
// we do both in one pass here, instead of using Storage.removeDir
bool FileBrowserActivity::removeDirFile(const std::string& fullPath) {
  auto file = Storage.open(fullPath.c_str());
  if (!file) {
    LOG_ERR("FileBrowser", "Failed to open for metadata clearing: %s", fullPath.c_str());
    return false;
  }

  if (!file.isDirectory()) {
    file.close();
    clearBookCache(fullPath);
    return Storage.remove(fullPath.c_str());
  }
  file.close();

  if (!fileNameBuffer) {
    LOG_ERR("FileBrowser", "fileNameBuffer not allocated");
    return false;
  }

  // Stack of (dirPath, postOrder): postOrder=true means rmdir this path after children are processed.
  std::vector<std::pair<std::string, bool>> stack;
  stack.reserve(16);
  stack.push_back({fullPath, false});

  while (!stack.empty()) {
    auto [currentPath, postOrder] = std::move(stack.back());
    stack.pop_back();

    if (postOrder) {
      if (!Storage.rmdir(currentPath.c_str())) {
        LOG_ERR("FileBrowser", "Failed to rmdir: %s", currentPath.c_str());
        return false;
      }
      continue;
    }

    auto dir = Storage.open(currentPath.c_str());
    if (!dir) {
      LOG_ERR("FileBrowser", "Failed to open dir: %s", currentPath.c_str());
      return false;
    }
    if (!dir.isDirectory()) {
      LOG_ERR("FileBrowser", "Not a directory: %s", currentPath.c_str());
      return false;
    }

    // Push this dir for post-order rmdir (after all children are processed).
    stack.push_back({currentPath, true});

    dir.rewindDirectory();
    for (auto entry = dir.openNextFile(); entry; entry = dir.openNextFile()) {
      entry.getName(fileNameBuffer.get(), NAME_BUFFER_SIZE);
      if (strcmp(fileNameBuffer.get(), ".") == 0 || strcmp(fileNameBuffer.get(), "..") == 0) {
        continue;
      }
      std::string entryPath = currentPath;
      if (entryPath.back() != '/') {
        entryPath += "/";
      }
      entryPath += fileNameBuffer.get();

      const bool isDir = entry.isDirectory();
      entry.close();

      if (isDir) {
        stack.push_back({std::move(entryPath), false});
      } else {
        clearBookCache(entryPath);
        if (!Storage.remove(entryPath.c_str())) {
          LOG_ERR("FileBrowser", "Failed to remove file: %s", entryPath.c_str());
          return false;
        }
      }
    }
  }

  return true;
}

void FileBrowserActivity::loop() {
  // Long press BACK (1s+) goes to root folder (Books mode, folder view only — flat view has no
  // folder concept to go "up" out of; Back there always means Home, handled below).
  if (mode == Mode::Books && !inAllBooksView() && mappedInput.isPressed(MappedInputManager::Button::Back) &&
      mappedInput.getHeldTime() >= GO_HOME_MS && basepath != "/" && !lockLongPressBack) {
    basepath = "/";
    loadFiles();
    selectorIndex = hasTabBar() ? 1 : 0;
    requestUpdate();
    return;
  }

  if (lockLongPressBack && mappedInput.wasReleased(MappedInputManager::Button::Back)) {
    lockLongPressBack = false;
    return;
  }

  // Swallows the Back release that follows an aborted lazy-indexing pass (see render()) so it
  // doesn't also trigger "go up a directory" / "go home" on the same press.
  if (lockNextBackRelease && mappedInput.wasReleased(MappedInputManager::Button::Back)) {
    lockNextBackRelease = false;
    return;
  }

  const int pageItems = getPageItems();

  if (mappedInput.wasReleased(MappedInputManager::Button::Confirm)) {
    if (lockNextConfirmRelease) {
      lockNextConfirmRelease = false;
      return;
    }

    if (hasTabBar() && selectorIndex == 0) {
      toggleViewMode();
      requestUpdate();
      return;
    }

    if (inAllBooksView()) {
      const auto& entries = flatBooks->getEntries();
      const size_t rowIndex = selectorIndex - 1;
      if (entries.empty() || rowIndex >= entries.size()) return;
      const std::string path = entries[rowIndex].path;

      if (mappedInput.getHeldTime() >= GO_HOME_MS) {
        // --- LONG PRESS ACTION: DELETE BOOK ---
        auto handler = [this, path, rowIndex](const ActivityResult& res) {
          if (!res.isCancelled) {
            LOG_DBG("FileBrowser", "Attempting to delete: %s", path.c_str());
            if (removeDirFile(path)) {
              LOG_DBG("FileBrowser", "Deleted successfully");
              flatBooks->removeAt(rowIndex);
              if (flatBooks->size() == 0) {
                selectorIndex = 0;
              } else if (rowIndex >= flatBooks->size()) {
                // Move selection to the new "last" row (slot index = row + 1 for the tab bar).
                selectorIndex = flatBooks->size();
              }
              indexAbortedPage = SIZE_MAX;
              requestUpdate(true);
            } else {
              LOG_ERR("FileBrowser", "Failed to delete: %s", path.c_str());
            }
          } else {
            LOG_DBG("FileBrowser", "Delete cancelled by user");
          }
        };

        std::string heading = tr(STR_DELETE) + std::string("? ");
        startActivityForResult(std::make_unique<ConfirmationActivity>(renderer, mappedInput, heading, basenameOf(path)),
                               handler);
        return;
      }

      // --- SHORT PRESS ACTION: OPEN ---
      onSelectBook(path);
      return;
    }

    if (files.empty()) return;

    const size_t rowIndex = hasTabBar() ? selectorIndex - 1 : selectorIndex;
    const std::string& entry = files[rowIndex];
    bool isDirectory = (entry.back() == '/');

    // Firmware picker: select file -> return path; navigate into directories normally.
    if (mode == Mode::PickFirmware && !isDirectory) {
      std::string cleanBasePath = basepath;
      if (cleanBasePath.back() != '/') cleanBasePath += "/";
      ActivityResult res{FilePathResult{cleanBasePath + entry}};
      res.isCancelled = false;
      setResult(std::move(res));
      finish();
      return;
    }

    if (mode == Mode::Books && mappedInput.getHeldTime() >= GO_HOME_MS) {
      // --- LONG PRESS ACTION: DELETE FILE OR DIRECTORY ---
      std::string cleanBasePath = basepath;
      if (cleanBasePath.back() != '/') cleanBasePath += "/";
      const std::string fullPath = cleanBasePath + entry;

      auto handler = [this, fullPath, rowIndex](const ActivityResult& res) {
        if (!res.isCancelled) {
          LOG_DBG("FileBrowser", "Attempting to delete: %s", fullPath.c_str());
          if (removeDirFile(fullPath)) {
            LOG_DBG("FileBrowser", "Deleted successfully");
            loadFiles();
            if (files.empty()) {
              selectorIndex = 0;
            } else if (rowIndex >= files.size()) {
              // Move selection to the new "last" item
              selectorIndex = files.size() - 1 + (hasTabBar() ? 1 : 0);
            }

            requestUpdate(true);
          } else {
            LOG_ERR("FileBrowser", "Failed to delete: %s", fullPath.c_str());
          }
        } else {
          LOG_DBG("FileBrowser", "Delete cancelled by user");
        }
      };

      std::string heading = tr(STR_DELETE) + std::string("? ");

      startActivityForResult(std::make_unique<ConfirmationActivity>(renderer, mappedInput, heading, entry), handler);
      return;
    } else {
      // --- SHORT PRESS ACTION: OPEN/NAVIGATE ---
      if (basepath.back() != '/') basepath += "/";

      if (isDirectory) {
        basepath += entry.substr(0, entry.length() - 1);
        loadFiles();
        selectorIndex = hasTabBar() ? 1 : 0;
        requestUpdate();
      } else {
        onSelectBook(basepath + entry);
      }
    }
    return;
  }

  if (mappedInput.wasReleased(MappedInputManager::Button::Back)) {
    // Short press: go up one directory, or go home if at root
    if (mappedInput.getHeldTime() < GO_HOME_MS) {
      if (inAllBooksView()) {
        onGoHome();
      } else if (basepath != "/") {
        const std::string oldPath = basepath;

        basepath.replace(basepath.find_last_of('/'), std::string::npos, "");
        if (basepath.empty()) basepath = "/";
        loadFiles();

        const auto pos = oldPath.find_last_of('/');
        const std::string dirName = oldPath.substr(pos + 1) + "/";
        selectorIndex = findEntry(dirName) + (hasTabBar() ? 1 : 0);

        requestUpdate();
      } else if (mode == Mode::PickFirmware) {
        // Firmware picker at root: cancel back to caller instead of going home.
        ActivityResult res;
        res.isCancelled = true;
        setResult(std::move(res));
        finish();
      } else {
        onGoHome();
      }
    }
  }

  const int totalSlots = static_cast<int>(itemCount()) + (hasTabBar() ? 1 : 0);
  buttonNavigator.onNextRelease([this, totalSlots] {
    selectorIndex = ButtonNavigator::nextIndex(static_cast<int>(selectorIndex), totalSlots);
    requestUpdate();
  });

  buttonNavigator.onPreviousRelease([this, totalSlots] {
    selectorIndex = ButtonNavigator::previousIndex(static_cast<int>(selectorIndex), totalSlots);
    requestUpdate();
  });

  buttonNavigator.onNextContinuous([this, totalSlots, pageItems] {
    selectorIndex = ButtonNavigator::nextPageIndex(static_cast<int>(selectorIndex), totalSlots, pageItems);
    requestUpdate();
  });

  buttonNavigator.onPreviousContinuous([this, totalSlots, pageItems] {
    selectorIndex = ButtonNavigator::previousPageIndex(static_cast<int>(selectorIndex), totalSlots, pageItems);
    requestUpdate();
  });
}

std::string getFileName(std::string filename) {
  if (filename.back() == '/') {
    filename.pop_back();
    if (!UITheme::getInstance().getTheme().showsFileIcons()) {
      return "[" + filename + "]";
    }
    return filename;
  }
  const auto pos = filename.rfind('.');
  return filename.substr(0, pos);
}

std::string getFileExtension(const std::string& filename) {
  if (filename.back() == '/') {
    return "";
  }
  const auto pos = filename.rfind('.');
  return filename.substr(pos);
}

void FileBrowserActivity::render(RenderLock&&) {
  renderer.clearScreen();

  const auto pageWidth = renderer.getScreenWidth();
  const auto pageHeight = renderer.getScreenHeight();
  const auto& metrics = UITheme::getInstance().getMetrics();

  const bool flatView = inAllBooksView();
  const bool coversStyle = flatView && SETTINGS.allBooksViewStyle == CrossPointSettings::ALL_BOOKS_COVERS;

  std::string headerTitle;
  if (mode == Mode::PickFirmware) {
    headerTitle = tr(STR_SELECT_FIRMWARE_FILE);
  } else if (flatView) {
    headerTitle = tr(STR_ALL_BOOKS);
  } else {
    headerTitle = (basepath == "/") ? std::string(tr(STR_SD_CARD)) : basepath.substr(basepath.rfind('/') + 1);
  }
  GUI.drawHeader(renderer, Rect{0, metrics.topPadding, pageWidth, metrics.headerHeight}, headerTitle.c_str());

  int contentTop = metrics.topPadding + metrics.headerHeight;
  if (hasTabBar()) {
    const std::vector<TabInfo> tabs = {
        {tr(STR_FOLDERS), !flatView},
        {tr(STR_ALL_BOOKS), flatView},
    };
    GUI.drawTabBar(renderer, Rect{0, contentTop, pageWidth, metrics.tabBarHeight}, tabs, selectorIndex == 0);
    contentTop += metrics.tabBarHeight;
  }

  const int pathLineHeight = renderer.getLineHeight(SMALL_FONT_ID);
  const int pathReserved = pathLineHeight + metrics.verticalSpacing;
  const int contentHeight =
      pageHeight - contentTop - metrics.buttonHintsHeight - metrics.verticalSpacing - pathReserved;

  const size_t total = itemCount();
  const int rowSelIndex = hasTabBar() ? static_cast<int>(selectorIndex) - 1 : static_cast<int>(selectorIndex);

  if (total == 0) {
    const char* emptyMsg = (mode == Mode::PickFirmware) ? tr(STR_NO_BIN_FILES) : tr(STR_NO_FILES_FOUND);
    renderer.drawText(UI_10_FONT_ID, metrics.contentSidePadding, contentTop + 20, emptyMsg);
  } else if (flatView) {
    const auto& entries = flatBooks->getEntries();
    if (coversStyle) {
      GUI.drawBookList(renderer, Rect{0, contentTop, pageWidth, contentHeight}, static_cast<int>(entries.size()),
                       rowSelIndex, [&entries](int index) {
                         const auto& e = entries[index];
                         return BookListRowData{FlatBookList::displayTitle(e), e.author, e.thumbPath, UIIcon::Book};
                       });
    } else {
      GUI.drawList(
          renderer, Rect{0, contentTop, pageWidth, contentHeight}, static_cast<int>(entries.size()), rowSelIndex,
          [&entries](int index) { return FlatBookList::displayTitle(entries[index]); },
          [&entries](int index) { return entries[index].author; });
    }
  } else {
    GUI.drawList(
        renderer, Rect{0, contentTop, pageWidth, contentHeight}, files.size(), rowSelIndex,
        [this](int index) { return getFileName(files[index]); }, nullptr,
        [this](int index) { return UITheme::getFileIcon(files[index]); },
        [this](int index) { return getFileExtension(files[index]); }, false);
  }

  // Full path display: for flat view this shows the selected book's parent folder rather than
  // a browsing basepath (there is no folder concept to browse in the flat listing).
  {
    const int pathY = pageHeight - metrics.buttonHintsHeight - metrics.verticalSpacing - pathLineHeight;
    const int separatorY = pathY - metrics.verticalSpacing / 2;
    renderer.drawLine(0, separatorY, pageWidth - 1, separatorY, 3, true);
    const int pathMaxWidth = pageWidth - metrics.contentSidePadding * 2;

    std::string pathValue = basepath;
    if (flatView) {
      const auto& entries = flatBooks->getEntries();
      pathValue = (rowSelIndex >= 0 && static_cast<size_t>(rowSelIndex) < entries.size())
                      ? FsHelpers::extractFolderPath(entries[rowSelIndex].path)
                      : "/";
    }

    // Left-truncate so the deepest directory is always visible
    const char* pathStr = pathValue.c_str();
    const char* pathDisplay = pathStr;
    char leftTruncBuf[256];
    if (renderer.getTextWidth(SMALL_FONT_ID, pathStr) > pathMaxWidth) {
      const char ellipsis[] = "\xe2\x80\xa6";  // UTF-8 ellipsis (…)
      const int ellipsisWidth = renderer.getTextWidth(SMALL_FONT_ID, ellipsis);
      const int available = pathMaxWidth - ellipsisWidth;
      // Walk forward from the start until the suffix fits, skipping UTF-8 continuation bytes
      const char* p = pathStr;
      while (*p) {
        if (renderer.getTextWidth(SMALL_FONT_ID, p) <= available) break;
        ++p;
        while (*p && (static_cast<unsigned char>(*p) & 0xC0) == 0x80) ++p;
      }
      snprintf(leftTruncBuf, sizeof(leftTruncBuf), "%s%s", ellipsis, p);
      pathDisplay = leftTruncBuf;
    }
    renderer.drawText(SMALL_FONT_ID, metrics.contentSidePadding, pathY, pathDisplay);
  }

  // Help text
  const bool emptyForHints = flatView ? (total == 0) : files.empty();
  const char* backLabel =
      flatView ? tr(STR_HOME)
               : ((basepath == "/") ? (mode == Mode::PickFirmware ? tr(STR_BACK) : tr(STR_HOME)) : tr(STR_BACK));
  // In PickFirmware mode, Confirm on a .bin returns the path to the caller (not "open"); show
  // STR_SELECT instead. Directories in the same picker still descend, so keep STR_OPEN there.
  const bool selectingFirmwareFile =
      mode == Mode::PickFirmware && !emptyForHints && rowSelIndex >= 0 && files[rowSelIndex].back() != '/';
  const char* confirmLabel = emptyForHints ? "" : (selectingFirmwareFile ? tr(STR_SELECT) : tr(STR_OPEN));
  if (hasTabBar() && selectorIndex == 0) {
    // On the tab bar row Confirm toggles Folders/All books, not open/navigate.
    confirmLabel = tr(STR_TOGGLE);
  }
  const auto labels = mappedInput.mapLabels(backLabel, confirmLabel, emptyForHints ? "" : tr(STR_DIR_UP),
                                            emptyForHints ? "" : tr(STR_DIR_DOWN));
  GUI.drawButtonHints(renderer, labels.btn1, labels.btn2, labels.btn3, labels.btn4);

  renderer.displayBuffer();

  // Lazy metadata/thumbnail indexing for the visible page (flat view only). Runs after
  // displayBuffer() so the (possibly stale) list is visible immediately; if any row actually
  // needed work, requestUpdate() triggers a follow-up render showing the resolved data.
  if (flatView && flatBooks) {
    const int pageItems = getPageItems();
    const size_t page = pageItems > 0 ? static_cast<size_t>(std::max(0, rowSelIndex)) / pageItems : 0;
    const size_t start = page * static_cast<size_t>(pageItems);

    if (page != indexAbortedPage) {
      indexAbortedPage = SIZE_MAX;  // moving to a different page always clears the suppression
      if (flatBooks->pageNeedsWork(start, static_cast<size_t>(pageItems), coversStyle)) {
        bool aborted = false;
        const bool changed = flatBooks->ensureVisibleMetadata(renderer, mappedInput, start,
                                                              static_cast<size_t>(pageItems), coversStyle, aborted);
        if (aborted) {
          indexAbortedPage = page;
          lockNextBackRelease = true;
        }
        if (changed) {
          requestUpdate();
        }
      }
    }
  }
}

size_t FileBrowserActivity::findEntry(const std::string& name) const {
  for (size_t i = 0; i < files.size(); i++)
    if (files[i] == name) return i;
  return 0;
}
