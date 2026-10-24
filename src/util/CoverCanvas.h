#pragma once

#include <cstdint>
#include <cstring>

// Square 1-bit canvas that carries a book cover as a list-row icon.
//
// fui::list draws a row icon into a square slot, one bit per pixel, set bit =
// ink (BitmapFormat::BW1, rows MSB-first). A cover is taller than it is wide,
// so it sits at the canvas's left edge and the right part stays blank; the list
// caller pulls the row text back over that blank part with a negative text gap.
// Pure bit twiddling, kept free of SDK types so host tests can cover it.
namespace cover_canvas {

constexpr int SIZE = 80;         // Canvas side, and the cover height
constexpr int COVER_WIDTH = 48;  // Thumbs are generated at 0.6 x height
constexpr int ROW_BYTES = (SIZE + 7) / 8;
constexpr int BYTES = ROW_BYTES * SIZE;
static_assert(COVER_WIDTH % 8 == 0, "invert() flips whole bytes");

inline void clear(uint8_t* canvas) { memset(canvas, 0, BYTES); }

inline void setInk(uint8_t* canvas, const int x, const int y) {
  if (x < 0 || x >= SIZE || y < 0 || y >= SIZE) return;
  canvas[y * ROW_BYTES + x / 8] |= static_cast<uint8_t>(0x80 >> (x % 8));
}

inline bool inkAt(const uint8_t* canvas, const int x, const int y) {
  if (x < 0 || x >= SIZE || y < 0 || y >= SIZE) return false;
  return (canvas[y * ROW_BYTES + x / 8] & (0x80 >> (x % 8))) != 0;
}

// 1px outline of the cover area.
inline void frame(uint8_t* canvas) {
  for (int x = 0; x < COVER_WIDTH; ++x) {
    setInk(canvas, x, 0);
    setInk(canvas, x, SIZE - 1);
  }
  for (int y = 0; y < SIZE; ++y) {
    setInk(canvas, 0, y);
    setInk(canvas, COVER_WIDTH - 1, y);
  }
}

// Copies a 1-bit icon (rows MSB-first, padded to whole bytes) centered on the
// cover area. inkIsZero selects the Mask1 polarity used by SDK icons.
inline void blitCentered(uint8_t* canvas, const uint8_t* bits, const int width, const int height,
                         const bool inkIsZero) {
  const int bytesPerRow = (width + 7) / 8;
  const int x0 = (COVER_WIDTH - width) / 2;
  const int y0 = (SIZE - height) / 2;
  for (int y = 0; y < height; ++y) {
    for (int x = 0; x < width; ++x) {
      const bool bit = (bits[y * bytesPerRow + x / 8] >> (7 - x % 8)) & 0x01;
      if (bit != inkIsZero) setInk(canvas, x0 + x, y0 + y);
    }
  }
}

// Copy of the canvas with the cover area flipped, for rows that draw their
// icon in white on a black selection fill: the cover then reads the right way
// round. The blank part stays blank so no white block appears beside it.
inline void invert(const uint8_t* canvas, uint8_t* out) {
  memcpy(out, canvas, BYTES);
  for (int y = 0; y < SIZE; ++y) {
    for (int b = 0; b < COVER_WIDTH / 8; ++b) out[y * ROW_BYTES + b] ^= 0xFF;
  }
}

}  // namespace cover_canvas
