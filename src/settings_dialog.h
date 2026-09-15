#pragma once
#include "common.h"
#include "ui_layout.h"
#include <commctrl.h>

namespace nl {
// Owns only the viewport/font; the modal dialog owns all HWNDs. Body controls are
// reparented, so callers MUST use Body() for GetDlgItem / CheckDlgButton etc.
class SettingsDialogLayout {
    struct Item { HWND hwnd; int y = 0, height = 0; bool combo = false; };
    HWND dialog_, body_ = nullptr;
    HBRUSH background_;
    HFONT font_ = nullptr;
    LOGFONTW originalFont_{};
    UINT dpi_ = 96, originalDpi_ = 96;
    int offset_ = 0, contentHeight_ = 0, page_ = 0, wheel_ = 0;
    std::vector<Item> items_;
    int Px(int n) const { return (std::max)(1, MulDiv(n, dpi_, 96)); }
    static UINT Dpi(HWND h) {
        using Fn = UINT(WINAPI*)(HWND);
        auto fn = reinterpret_cast<Fn>(GetProcAddress(GetModuleHandleW(L"user32.dll"), "GetDpiForWindow"));
        if (fn) return fn(h);
        HDC dc = GetDC(h);
        UINT dpi = GetDeviceCaps(dc, LOGPIXELSY);
        ReleaseDC(h, dc);
        return dpi ? dpi : 96;
    }
    int TextHeight(HWND h, int width) const {
        wchar_t text[2048]{};
        GetWindowTextW(h, text, 2048);
        HDC dc = GetDC(h);
        auto old = SelectObject(dc, reinterpret_cast<HFONT>(SendMessageW(h, WM_GETFONT, 0, 0)));
        RECT r{0, 0, (std::max)(1, width), 0};
        DrawTextW(dc, text, -1, &r, DT_CALCRECT | DT_WORDBREAK | DT_NOPREFIX | DT_EDITCONTROL);
        TEXTMETRICW tm{};
        GetTextMetricsW(dc, &tm);
        SelectObject(dc, old);
        ReleaseDC(h, dc);
        return (std::max)((int)tm.tmHeight, (int)r.bottom);
    }
    void PositionItems() {
        RECT rc{}; GetClientRect(body_, &rc);
        for (const auto& i : items_)
            SetWindowPos(i.hwnd, nullptr, Px(12), i.y - offset_, (std::max)(1, (int)rc.right - 2 * Px(12)),
                         i.combo ? Px(200) : i.height, SWP_NOZORDER | SWP_NOACTIVATE);
        InvalidateRect(body_, nullptr, TRUE);
    }
    void ScrollTo(int position) {
        offset_ = (std::max)(0, (std::min)(position, (std::max)(0, contentHeight_ - page_)));
        SetScrollPos(body_, SB_VERT, offset_, TRUE);
        PositionItems();
    }
    void Reveal(HWND child) {
        for (const auto& i : items_) if (i.hwnd == child) {
            if (i.y < offset_) ScrollTo(i.y);
            else if (i.y + i.height > offset_ + page_) ScrollTo(i.y + i.height - page_);
            break;
        }
    }
    void Wheel(WPARAM wp) {
        wheel_ += GET_WHEEL_DELTA_WPARAM(wp);
        const int notches = wheel_ / WHEEL_DELTA;
        wheel_ %= WHEEL_DELTA;
        UINT lines = 3;
        SystemParametersInfoW(SPI_GETWHEELSCROLLLINES, 0, &lines, 0);
        const int step = lines == WHEEL_PAGESCROLL ? (std::max)(1, page_ - Px(24)) : (int)lines * Px(20);
        if (notches) ScrollTo(offset_ - notches * step);
    }
    static LRESULT CALLBACK ChildProc(HWND h, UINT msg, WPARAM wp, LPARAM lp, UINT_PTR id, DWORD_PTR data) {
        auto* s = reinterpret_cast<SettingsDialogLayout*>(data);
        if (msg == WM_SETFOCUS) s->Reveal(h);
        if (msg == WM_MOUSEWHEEL && !SendMessageW(h, CB_GETDROPPEDSTATE, 0, 0)) {
            s->Wheel(wp); return 0;
        }
        if (msg == WM_NCDESTROY) RemoveWindowSubclass(h, ChildProc, id);
        return DefSubclassProc(h, msg, wp, lp);
    }
    static LRESULT CALLBACK BodyProc(HWND h, UINT msg, WPARAM wp, LPARAM lp) {
        auto* s = reinterpret_cast<SettingsDialogLayout*>(GetWindowLongPtrW(h, GWLP_USERDATA));
        if (msg == WM_NCCREATE) {
            s = static_cast<SettingsDialogLayout*>(reinterpret_cast<CREATESTRUCTW*>(lp)->lpCreateParams);
            SetWindowLongPtrW(h, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(s));
        }
        if (!s) return DefWindowProcW(h, msg, wp, lp);
        switch (msg) {
        case WM_COMMAND:
        case WM_CTLCOLORSTATIC:
        case WM_CTLCOLORBTN:
        case WM_CTLCOLOREDIT:
        case WM_CTLCOLORLISTBOX:
            return SendMessageW(s->dialog_, msg, wp, lp);
        case WM_ERASEBKGND: {
            RECT r{}; GetClientRect(h, &r); FillRect(reinterpret_cast<HDC>(wp), &r, s->background_); return 1;
        }
        case WM_MOUSEWHEEL: s->Wheel(wp); return 0;
        case WM_VSCROLL: {
            int pos = s->offset_;
            switch (LOWORD(wp)) {
            case SB_LINEUP: pos -= s->Px(24); break;
            case SB_LINEDOWN: pos += s->Px(24); break;
            case SB_PAGEUP: pos -= s->page_; break;
            case SB_PAGEDOWN: pos += s->page_; break;
            case SB_TOP: pos = 0; break;
            case SB_BOTTOM: pos = s->contentHeight_; break;
            case SB_THUMBTRACK: case SB_THUMBPOSITION: {
                SCROLLINFO si{sizeof(si), SIF_TRACKPOS}; GetScrollInfo(h, SB_VERT, &si); pos = si.nTrackPos; break;
            }
            default: return 0;
            }
            s->ScrollTo(pos); return 0;
        }
        }
        return DefWindowProcW(h, msg, wp, lp);
    }
public:
    SettingsDialogLayout(HWND dialog, HBRUSH background) : dialog_(dialog), background_(background) {}
    ~SettingsDialogLayout() { if (font_) DeleteObject(font_); }
    HWND Body() const { return body_; }
    bool Initialize() {
        dpi_ = originalDpi_ = Dpi(dialog_);
        GetObjectW(reinterpret_cast<HFONT>(SendMessageW(dialog_, WM_GETFONT, 0, 0)), sizeof(originalFont_), &originalFont_);
        // This dialog has its own DPI reflow; avoid the dialog manager scaling it twice.
        using Behavior = BOOL(WINAPI*)(HWND, int, int);
        auto behavior = reinterpret_cast<Behavior>(GetProcAddress(GetModuleHandleW(L"user32.dll"), "SetDialogDpiChangeBehavior"));
        if (behavior) behavior(dialog_, 1, 1); // DDC_DISABLE_ALL
        WNDCLASSW wc{};
        wc.lpfnWndProc = BodyProc;
        wc.hInstance = reinterpret_cast<HINSTANCE>(GetWindowLongPtrW(dialog_, GWLP_HINSTANCE));
        wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
        wc.lpszClassName = L"NetLurker.SettingsViewport";
        if (!RegisterClassW(&wc) && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) return false;
        // Collect first, before reparenting changes the sibling chain.
        for (HWND h = GetWindow(dialog_, GW_CHILD); h; h = GetWindow(h, GW_HWNDNEXT))
            if (GetDlgCtrlID(h) != IDOK && GetDlgCtrlID(h) != IDCANCEL) items_.push_back({h});
        body_ = CreateWindowExW(WS_EX_CONTROLPARENT, wc.lpszClassName, L"", WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_CLIPCHILDREN,
                               0, 0, 1, 1, dialog_, nullptr, wc.hInstance, this);
        if (!body_) return false;
        SetWindowPos(body_, HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
        for (auto& i : items_) {
            SetParent(i.hwnd, body_);
            SetWindowPos(i.hwnd, HWND_BOTTOM, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
            SetWindowSubclass(i.hwnd, ChildProc, 1, reinterpret_cast<DWORD_PTR>(this));
            wchar_t cls[32]{}; GetClassNameW(i.hwnd, cls, 32);
            i.combo = _wcsicmp(cls, L"ComboBox") == 0;
            if (_wcsicmp(cls, L"Button") == 0)
                SetWindowLongPtrW(i.hwnd, GWL_STYLE, GetWindowLongPtrW(i.hwnd, GWL_STYLE) | BS_MULTILINE);
            if (_wcsicmp(cls, L"Edit") == 0) SendMessageW(i.hwnd, EM_SETLIMITTEXT, 1023, 0);
        }
        for (int id : {IDOK, IDCANCEL}) {
            HWND h = GetDlgItem(dialog_, id);
            SetWindowLongPtrW(h, GWL_STYLE, GetWindowLongPtrW(h, GWL_STYLE) | BS_MULTILINE);
        }
        RECT window{}; GetWindowRect(dialog_, &window);
        Clamp(window, true);
        Layout();
        return true;
    }
    void Clamp(RECT suggested, bool center = false) {
        MONITORINFO mi{sizeof(mi)};
        GetMonitorInfoW(MonitorFromRect(&suggested, MONITOR_DEFAULTTONEAREST), &mi);
        const RECT& wa = mi.rcWork;
        const int w = (std::min)((int)(suggested.right - suggested.left), (int)(wa.right - wa.left));
        const int h = (std::min)((int)(suggested.bottom - suggested.top), (int)(wa.bottom - wa.top));
        const int x = center ? wa.left + (wa.right - wa.left - w) / 2 : (std::max)((int)wa.left, (std::min)((int)suggested.left, (int)wa.right - w));
        const int y = center ? wa.top + (wa.bottom - wa.top - h) / 2 : (std::max)((int)wa.top, (std::min)((int)suggested.top, (int)wa.bottom - h));
        SetWindowPos(dialog_, nullptr, x, y, w, h, SWP_NOZORDER | SWP_NOACTIVATE);
    }
    void MinMax(MINMAXINFO* mm) const {
        MONITORINFO mi{sizeof(mi)};
        GetMonitorInfoW(MonitorFromWindow(dialog_, MONITOR_DEFAULTTONEAREST), &mi);
        mm->ptMinTrackSize = {(std::min)(Px(360), (int)(mi.rcWork.right - mi.rcWork.left)),
                              (std::min)(Px(240), (int)(mi.rcWork.bottom - mi.rcWork.top))};
    }
    void ChangeDpi(UINT dpi, RECT suggested) {
        dpi_ = dpi ? dpi : 96;
        LOGFONTW lf = originalFont_;
        lf.lfHeight = MulDiv(lf.lfHeight, dpi_, originalDpi_);
        HFONT font = CreateFontIndirectW(&lf);
        if (font) {
            SendMessageW(dialog_, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
            for (const auto& i : items_) SendMessageW(i.hwnd, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
            for (int id : {IDOK, IDCANCEL}) SendDlgItemMessageW(dialog_, id, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
            if (font_) DeleteObject(font_);
            font_ = font;
        }
        Clamp(suggested);
        Layout();
    }
    void Layout() {
        if (!body_) return;
        RECT r{}; GetClientRect(dialog_, &r);
        const int margin = Px(12);
        const int bw = (std::max)(1, ((int)r.right - 3 * margin) / 2);
        const int buttonHeight = (std::max)(Px(36), (std::max)(TextHeight(GetDlgItem(dialog_, IDOK), bw - Px(16)),
                                      TextHeight(GetDlgItem(dialog_, IDCANCEL), bw - Px(16))) + Px(12));
        auto frame = PlaceSettingsFrame(r.right, r.bottom, margin, buttonHeight);
        auto place = [](HWND h, const FlowItem& f) { SetWindowPos(h, nullptr, f.x, f.y, f.width, f.height, SWP_NOZORDER | SWP_NOACTIVATE); };
        place(GetDlgItem(dialog_, IDOK), frame.save);
        place(GetDlgItem(dialog_, IDCANCEL), frame.cancel);
        place(body_, frame.body);
        // Always reserve the scrollbar width, including when disabled, to avoid a reflow loop.
        SCROLLINFO si{sizeof(si), SIF_RANGE | SIF_PAGE | SIF_POS | SIF_DISABLENOSCROLL};
        si.nMin = 0; si.nMax = 1; si.nPage = 1;
        SetScrollInfo(body_, SB_VERT, &si, TRUE);
        RECT br{}; GetClientRect(body_, &br);
        const int width = (std::max)(1, (int)br.right - 2 * margin);
        int y = margin;
        for (auto& i : items_) {
            wchar_t cls[32]{}; GetClassNameW(i.hwnd, cls, 32);
            const bool edit = _wcsicmp(cls, L"Edit") == 0;
            const bool check = _wcsicmp(cls, L"Button") == 0;
            i.y = y;
            i.height = edit || i.combo ? (std::max)(Px(28), TextHeight(i.hwnd, 100000) + Px(10))
                                     : TextHeight(i.hwnd, width - (check ? Px(28) : 0)) + (check ? Px(10) : 0);
            y += i.height + Px(6);
        }
        contentHeight_ = y + margin;
        page_ = br.bottom;
        offset_ = (std::min)(offset_, (std::max)(0, contentHeight_ - page_));
        si.nMax = (std::max)(0, contentHeight_ - 1); si.nPage = page_; si.nPos = offset_;
        SetScrollInfo(body_, SB_VERT, &si, TRUE);
        PositionItems();
        Reveal(GetFocus());
        InvalidateRect(dialog_, nullptr, TRUE);
    }
};
} // namespace nl
