#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

class GfxRenderer;
class MappedInputManager;

// Recursive, flat listing of every book on the SD card (epub/xtc/txt/md), backing the file
// browser's "All books" view. The directory walk happens once per activity lifetime (see scan());
// metadata (title/author) and cover thumbnails are resolved lazily, one visible page at a time,
// since eagerly building book.bin caches for hundreds of books would take far too long.
class FlatBookList {
 public:
  enum class Meta : uint8_t { Unknown, Loaded, None };

  struct Entry {
    std::string path;
    std::string title;
    std::string author;
    // Resolved thumb_<thumbHeightResolved>.bmp path; empty until resolved or unavailable at that
    // height. The List/Covers/Grid styles want different cached thumb heights (see
    // BaseTheme::bookListThumbHeight / bookGridThumbHeight), so a height switch (toggling the "All
    // Books Style" setting) must trigger re-resolution rather than reusing a mismatched thumb.
    std::string thumbPath;
    Meta meta = Meta::Unknown;  // None is terminal: txt/md (no metadata) or a failed/corrupt build
    // 0 = no thumbnail resolved yet for this entry; otherwise the height thumbPath was resolved at.
    // Only meaningful when meta == Loaded — entries with no metadata never have a thumbnail.
    int thumbHeightResolved = 0;
  };

  static constexpr size_t MAX_BOOKS = 300;

  // Recursively scans "/" for book files, skipping dot-entries and "System Volume Information".
  // Caller should draw a scanning popup before calling this — it walks the whole card and can
  // take a while. nameBuffer/bufferSize is a caller-owned scratch buffer for HalFile::getName
  // (reuse the file browser's existing buffer rather than allocating a second one).
  bool scan(char* nameBuffer, size_t bufferSize);

  // True if any row in [start, start + count) still needs metadata (or a thumbnail resolved at
  // wantThumbHeight, if wantThumbHeight != 0) resolved.
  bool pageNeedsWork(size_t start, size_t count, int wantThumbHeight) const;

  // Resolves metadata/thumbnails for the visible page only. Cheap (cache-hit) lookups happen
  // silently; the first row that needs a full uncached build triggers an "Indexing books" popup
  // with a progress bar for the rest of the page. Polls mappedInput between books and sets
  // aborted=true (stopping early) if Back is pressed. Returns true if anything changed and the
  // caller should re-render. wantThumbHeight of 0 skips thumbnail resolution entirely (List
  // style); otherwise resolves (or re-resolves, if a different height was previously cached in
  // this Entry) each row's thumbnail at that height.
  bool ensureVisibleMetadata(GfxRenderer& renderer, MappedInputManager& mappedInput, size_t start, size_t count,
                             int wantThumbHeight, bool& aborted);

  const std::vector<Entry>& getEntries() const { return entries; }
  size_t size() const { return entries.size(); }
  void removeAt(size_t index);
  void clear() { entries.clear(); }

  // Resolved title if known, otherwise the filename without its extension.
  static std::string displayTitle(const Entry& entry);

 private:
  std::vector<Entry> entries;
};
