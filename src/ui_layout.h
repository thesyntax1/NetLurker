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

} // namespace nl
