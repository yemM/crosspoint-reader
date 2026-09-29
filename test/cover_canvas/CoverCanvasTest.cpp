#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <utility>

#include "util/CoverCanvas.h"

namespace cc = cover_canvas;

namespace {
using Canvas = std::array<uint8_t, cc::BYTES>;

Canvas blank() {
  Canvas canvas{};
  cc::clear(canvas.data());
  return canvas;
}
}  // namespace

TEST(CoverCanvas, FrameOutlinesOnlyTheCoverArea) {
  auto canvas = blank();
  cc::frame(canvas.data());
  EXPECT_TRUE(cc::inkAt(canvas.data(), 0, 0));
  EXPECT_TRUE(cc::inkAt(canvas.data(), cc::COVER_WIDTH - 1, cc::SIZE - 1));
  EXPECT_TRUE(cc::inkAt(canvas.data(), 0, cc::SIZE / 2));
  EXPECT_FALSE(cc::inkAt(canvas.data(), cc::COVER_WIDTH / 2, cc::SIZE / 2));
  // The blank side the row text overlaps stays clear.
  for (int y = 0; y < cc::SIZE; ++y) {
    for (int x = cc::COVER_WIDTH; x < cc::SIZE; ++x) ASSERT_FALSE(cc::inkAt(canvas.data(), x, y)) << x << "," << y;
  }
}

TEST(CoverCanvas, SetInkIgnoresPixelsOutsideTheCanvas) {
  auto canvas = blank();
  cc::setInk(canvas.data(), -1, 0);
  cc::setInk(canvas.data(), 0, cc::SIZE);
  cc::setInk(canvas.data(), cc::SIZE, 3);
  EXPECT_EQ(canvas, blank());
}

TEST(CoverCanvas, BlitCentersIconOnCoverAndHonorsMaskPolarity) {
  // 8x2 icon, one ink pixel at (0, 0): BW1 sets the bit, Mask1 clears it.
  const uint8_t bw1[] = {0x80, 0x00};
  const uint8_t mask1[] = {0x7F, 0xFF};
  const int x0 = (cc::COVER_WIDTH - 8) / 2;
  const int y0 = (cc::SIZE - 2) / 2;
  for (const auto& [bits, inkIsZero] : {std::pair{bw1, false}, std::pair{mask1, true}}) {
    auto canvas = blank();
    cc::blitCentered(canvas.data(), bits, 8, 2, inkIsZero);
    EXPECT_TRUE(cc::inkAt(canvas.data(), x0, y0));
    EXPECT_FALSE(cc::inkAt(canvas.data(), x0 + 1, y0));
    EXPECT_FALSE(cc::inkAt(canvas.data(), x0, y0 + 1));
  }
}

TEST(CoverCanvas, InvertFlipsCoverAreaAndLeavesBlankSideClear) {
  auto canvas = blank();
  cc::setInk(canvas.data(), 3, 4);
  Canvas out{};
  cc::invert(canvas.data(), out.data());
  EXPECT_FALSE(cc::inkAt(out.data(), 3, 4));
  EXPECT_TRUE(cc::inkAt(out.data(), 4, 4));
  EXPECT_TRUE(cc::inkAt(out.data(), cc::COVER_WIDTH - 1, cc::SIZE - 1));
  for (int y = 0; y < cc::SIZE; ++y) {
    for (int x = cc::COVER_WIDTH; x < cc::SIZE; ++x) ASSERT_FALSE(cc::inkAt(out.data(), x, y)) << x << "," << y;
  }
  // The source canvas is untouched.
  EXPECT_TRUE(cc::inkAt(canvas.data(), 3, 4));
}
