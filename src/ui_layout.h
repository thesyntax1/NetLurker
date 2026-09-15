#pragma once

#include <algorithm>
#include <vector>

namespace nl {

// Pixel-space flow layout shared by measurement and hit testing. Keep this free of
// Win32 types so narrow-window / translated-label regressions can be tested on CI.
struct FlowItem {
    int x, y, width, height;
};
struct FlowLayout {
    std::vector<FlowItem> items;
    int height = 0;
};

inline FlowLayout PackToolbar(const std::vector<int>& widths, int available,
                              int itemHeight, int gap) {
    FlowLayout result;
    available = (std::max)(1, available);
    itemHeight = (std::max)(1, itemHeight);
    gap = (std::max)(0, gap);
    int x = 0, y = 0;
    for (int requested : widths) {
        const int width = (std::max)(1, (std::min)(requested, available));
        if (x > 0 && x + width > available) {
            x = 0;
            y += itemHeight + gap;
        }
        result.items.push_back({x, y, width, itemHeight});
        x += width + gap;
        result.height = y + itemHeight;
    }
    return result;
}

struct SettingsFrame {
    FlowItem body, save, cancel;
};

// Footer is measured first, then the remaining height belongs to the scroll viewport.
inline SettingsFrame PlaceSettingsFrame(int width, int height, int padding, int buttonHeight) {
    width = (std::max)(2, width);
    height = (std::max)(1, height);
    const int gap = (std::max)(0, (std::min)(padding, (width - 2) / 3));
    const int bottom = (std::min)(gap, height / 8);
    const int bh = (std::max)(1, (std::min)(buttonHeight, height - bottom));
    const int bw = (width - 3 * gap) / 2;
    const int y = height - bottom - bh;
    return {{0, 0, width, (std::max)(0, y - bottom)},
            {gap, y, bw, bh}, {2 * gap + bw, y, width - 3 * gap - bw, bh}};
}

} // namespace nl
