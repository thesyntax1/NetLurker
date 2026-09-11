#pragma once
#include "common.h"

namespace nl {

namespace clr {
    const COLORREF Bg        = RGB(13, 17, 23);
    const COLORREF Surface   = RGB(22, 27, 34);
    const COLORREF SurfaceHi = RGB(28, 34, 43);
    const COLORREF RowAlt    = RGB(17, 21, 28);
    const COLORREF RowHover  = RGB(31, 38, 48);
    const COLORREF RowSel    = RGB(30, 51, 84);
    const COLORREF Border    = RGB(41, 49, 61);
    const COLORREF Text      = RGB(230, 237, 243);
    const COLORREF TextDim   = RGB(139, 148, 158);
    const COLORREF TextFaint = RGB(100, 108, 118);
    const COLORREF Accent    = RGB(56, 139, 253);
    const COLORREF AccentDim = RGB(31, 82, 153);
    const COLORREF Green     = RGB(63, 185, 80);
    const COLORREF Yellow    = RGB(226, 168, 51);
    const COLORREF Orange    = RGB(219, 109, 40);
    const COLORREF Red       = RGB(248, 81, 73);
    const COLORREF Purple    = RGB(163, 113, 247);
    const COLORREF Cyan      = RGB(57, 197, 207);
}

class Painter {
public:
    Painter(HDC hdc);
    ~Painter();

    void FillRect(const RECT& r, COLORREF c);
    void FillRectAlpha(const RECT& r, COLORREF c, BYTE alpha);
    void FillRoundRect(const RECT& r, int radius, COLORREF c);
    void StrokeRoundRect(const RECT& r, int radius, COLORREF c, float width = 1.0f);
    void Line(int x1, int y1, int x2, int y2, COLORREF c, float width = 1.0f);
    void FillCircle(int cx, int cy, int r, COLORREF c);

    void Polyline(const std::vector<POINT>& pts, COLORREF c, float width = 1.5f);
    void FillPolygon(const std::vector<POINT>& pts, COLORREF c, BYTE alpha);

    void Text(const std::wstring& s, const RECT& r, HFONT font, COLORREF c,
              UINT format = DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
    SIZE Measure(const std::wstring& s, HFONT font);

    int  MeasureWrapped(const std::wstring& s, HFONT font, int width,
                        UINT format = DT_LEFT | DT_TOP | DT_WORDBREAK | DT_EDITCONTROL);

    HDC dc() const { return m_dc; }

private:
    HDC   m_dc;
    void* m_gfx;
};

void GdiPlusInit();
void GdiPlusShutdown();

}
