#include "ui_layout.h"

#include <cassert>
#include <iostream>
#include <random>

static void Check(const std::vector<int>& widths, int available, int height, int gap) {
    const auto layout = nl::PackToolbar(widths, available, height, gap);
    assert(layout.items.size() == widths.size());
    available = std::max(1, available);
    height = std::max(1, height);
    gap = std::max(0, gap);
    for (size_t i = 0; i < layout.items.size(); ++i) {
        const auto& item = layout.items[i];
        assert(item.x >= 0 && item.y >= 0);
        assert(item.width == std::max(1, std::min(widths[i], available)));
        assert(item.x + item.width <= available);
        assert(item.height == height);
        assert(item.y + item.height <= layout.height);
        for (size_t j = 0; j < i; ++j) {
            const auto& other = layout.items[j];
            assert(item.x >= other.x + other.width + gap ||
                   item.y >= other.y + other.height + gap);
        }
    }
}

int main() {
    assert(nl::PackToolbar({}, 900, 28, 6).height == 0);
    auto exact = nl::PackToolbar({100, 100}, 206, 28, 6);
    assert(exact.height == 28 && exact.items[1].x == 106);
    auto wrapped = nl::PackToolbar({100, 100}, 205, 28, 6);
    assert(wrapped.height == 62 && wrapped.items[1].x == 0);
    Check({0, -10, 900}, 0, 0, -1);

    // 11 filters, search, 7 actions: preserve every item at each supported DPI.
    const std::vector<int> toolbar = {42, 88, 70, 80, 90, 80, 60, 84, 46, 48, 48,
                                     180, 84, 74, 78, 72, 72, 112, 98};
    for (int dpi : {96, 120, 144, 192, 240, 288}) {
        for (int window : {900, 1024, 1180, 1366, 1560, 1920, 2560}) {
            for (int translationPercent : {100, 150, 200}) {
                std::vector<int> widths;
                for (int w : toolbar) widths.push_back(w * dpi / 96 * translationPercent / 100);
                Check(widths, (window - 24) * dpi / 96, 28 * dpi / 96, 6 * dpi / 96);
            }
        }
    }
    std::mt19937 random(42);
    for (int run = 0; run < 10000; ++run) {
        std::vector<int> widths;
        for (unsigned i = 0, n = random() % 40; i < n; ++i) widths.push_back(random() % 700);
        Check(widths, random() % 3000, 28, 6);
    }
    std::cout << "Toolbar layout: boundary cases, 126 DPI/translation cases, 10000 randomized cases passed\n";
}
