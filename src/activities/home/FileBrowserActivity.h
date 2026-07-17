#pragma once

#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "FlatBookList.h"
#include "RecentBooksStore.h"
#include "activities/Activity.h"
#include "util/ButtonNavigator.h"

struct Rect;

class FileBrowserActivity final : public Activity {
 public:
  // Books = standard reader browser; PickFirmware = filter to .bin only and return path via ActivityResult.
  enum class Mode { Books, PickFirmware };

 private:
  // Deletion
  bool removeDirFile(const std::string& fullPath);

  ButtonNavigator buttonNavigator;

  size_t selectorIndex = 0;

  bool lockLongPressBack = false;
  // True when this activity was entered while Confirm was already held; we must swallow the next
  // release so we don't immediately auto-open the first entry.
  bool lockNextConfirmRelease = false;

  Mode mode = Mode::Books;

  // Files state
  std::string basepath = "/";
  std::vector<std::string> files;
  std::unique_ptr<char[]> fileNameBuffer;

  // "All books" flat view state (Mode::Books only). Populated lazily: the recursive scan runs
  // once per activity lifetime (or on demand if the card wasn't scanned yet), metadata/thumbnails
  // resolve one visible page at a time from render().
  std::unique_ptr<FlatBookList> flatBooks;
  bool flatScanned = false;
  // Page index where lazy indexing was aborted (Back pressed mid-index); suppresses re-triggering
  // indexing every render while the user sits on that page. Cleared as soon as the page changes.
  size_t indexAbortedPage = SIZE_MAX;
  // Swallows the Back release that follows an aborted indexing pass, so it doesn't also trigger
  // "go up a directory" / "go home" on the same press.
  bool lockNextBackRelease = false;

  // Data loading
  void loadFiles();
  size_t findEntry(const std::string& name) const;

  // Tab bar + "All books" helpers
  bool hasTabBar() const { return mode == Mode::Books; }
  bool inAllBooksView() const;
  size_t itemCount() const;
  // Listing area rect shared by getPageItems() and render()'s draw calls.
  Rect listContentRect() const;
  int getPageItems() const;
  // Cached-thumbnail height (px) the active flat-view style needs, or 0 if it shows no thumbnails.
  int wantThumbHeight() const;
  void toggleViewMode();
  void enterAllBooksView(bool forceScan);

 public:
  explicit FileBrowserActivity(GfxRenderer& renderer, MappedInputManager& mappedInput, std::string initialPath = "/",
                               Mode mode = Mode::Books)
      : Activity("FileBrowser", renderer, mappedInput),
        mode(mode),
        basepath(initialPath.empty() ? "/" : std::move(initialPath)) {}
  void onEnter() override;
  void onExit() override;
  void loop() override;
  void render(RenderLock&&) override;
};
