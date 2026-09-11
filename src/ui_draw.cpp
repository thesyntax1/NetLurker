#include "ui_draw.h"

#include <objidl.h>
#include <gdiplus.h>

using namespace Gdiplus;

namespace nl {

static ULONG_PTR g_gdipToken = 0;

void GdiPlusInit() {
    if (g_gdipToken) return;
    GdiplusStartupInput in;
    GdiplusStartup(&g_gdipToken, &in, nullptr);
}

void GdiPlusShutdown() {
    if (!g_gdipToken) return;
    GdiplusShutdown(g_gdipToken);
    g_gdipToken = 0;
}

static Color C(COLORREF c, BYTE a = 255) {
    return Color(a, GetRValue(c), GetGValue(c), GetBValue(c));
}

Painter::Painter(HDC hdc) : m_dc(hdc), m_gfx(nullptr) {
    Graphics* g = new Graphics(hdc);
    g->SetSmoothingMode(SmoothingModeAntiAlias);
    g->SetPixelOffsetMode(PixelOffsetModeHalf);
    m_gfx = g;
}

Painter::~Painter() {
    delete reinterpret_cast<Graphics*>(m_gfx);
}

void Painter::FillRect(const RECT& r, COLORREF c) {
    SolidBrush b(C(c));
    Rect gr((INT)r.left, (INT)r.top, (INT)(r.right - r.left), (INT)(r.bottom - r.top));
    reinterpret_cast<Graphics*>(m_gfx)->FillRectangle(&b, gr);
}

static GraphicsPath* RoundPath(const RECT& r, int radius) {
    int w = (int)(r.right - r.left), h = (int)(r.bottom - r.top);
    int d = radius * 2;
    if (d > w) d = w;
    if (d > h) d = h;
    GraphicsPath* p = new GraphicsPath();
    if (d <= 1) {
        p->AddRectangle(Rect((INT)r.left, (INT)r.top, (INT)w, (INT)h));
        return p;
    }
    p->AddArc((INT)r.left, (INT)r.top, d, d, 180.0f, 90.0f);
    p->AddArc((INT)r.right - d, (INT)r.top, d, d, 270.0f, 90.0f);
    p->AddArc((INT)r.right - d, (INT)r.bottom - d, d, d, 0.0f, 90.0f);
    p->AddArc((INT)r.left, (INT)r.bottom - d, d, d, 90.0f, 90.0f);
    p->CloseFigure();
    return p;
}

void Painter::FillRectAlpha(const RECT& r, COLORREF c, BYTE alpha) {
    auto* g = static_cast<Gdiplus::Graphics*>(m_gfx);
    if (!g) return;
    Gdiplus::SolidBrush b(Gdiplus::Color(alpha, GetRValue(c), GetGValue(c), GetBValue(c)));
    g->FillRectangle(&b, Gdiplus::Rect((INT)r.left, (INT)r.top,
                                       (INT)(r.right - r.left), (INT)(r.bottom - r.top)));
}

void Painter::FillRoundRect(const RECT& r, int radius, COLORREF c) {
    if (r.right <= r.left || r.bottom <= r.top) return;
    GraphicsPath* p = RoundPath(r, radius);
    SolidBrush b(C(c));
    reinterpret_cast<Graphics*>(m_gfx)->FillPath(&b, p);
    delete p;
}

void Painter::StrokeRoundRect(const RECT& r, int radius, COLORREF c, float width) {
    if (r.right <= r.left || r.bottom <= r.top) return;
    RECT rr = r;
    rr.right -= 1; rr.bottom -= 1;
    GraphicsPath* p = RoundPath(rr, radius);
    Pen pen(C(c), width);
    reinterpret_cast<Graphics*>(m_gfx)->DrawPath(&pen, p);
    delete p;
}

void Painter::Line(int x1, int y1, int x2, int y2, COLORREF c, float width) {
    Pen pen(C(c), width);
    reinterpret_cast<Graphics*>(m_gfx)->DrawLine(&pen, x1, y1, x2, y2);
}

void Painter::FillCircle(int cx, int cy, int r, COLORREF c) {
    SolidBrush b(C(c));
    reinterpret_cast<Graphics*>(m_gfx)->FillEllipse(&b, cx - r, cy - r, r * 2, r * 2);
}

void Painter::Polyline(const std::vector<POINT>& pts, COLORREF c, float width) {
    if (pts.size() < 2) return;
    std::vector<Point> gp;
    gp.reserve(pts.size());
    for (auto& p : pts) gp.push_back(Point(p.x, p.y));
    Pen pen(C(c), width);
    pen.SetLineJoin(LineJoinRound);
    reinterpret_cast<Graphics*>(m_gfx)->DrawLines(&pen, gp.data(), (INT)gp.size());
}

void Painter::FillPolygon(const std::vector<POINT>& pts, COLORREF c, BYTE alpha) {
    if (pts.size() < 3) return;
    std::vector<Point> gp;
    gp.reserve(pts.size());
    for (auto& p : pts) gp.push_back(Point(p.x, p.y));
    SolidBrush b(C(c, alpha));
    reinterpret_cast<Graphics*>(m_gfx)->FillPolygon(&b, gp.data(), (INT)gp.size());
}

void Painter::Text(const std::wstring& s, const RECT& r, HFONT font, COLORREF c, UINT format) {
    if (s.empty()) return;
    HGDIOBJ old = SelectObject(m_dc, font);
    SetBkMode(m_dc, TRANSPARENT);
    SetTextColor(m_dc, c);
    RECT rc = r;
    DrawTextW(m_dc, s.c_str(), (int)s.size(), &rc, format);
    SelectObject(m_dc, old);
}

SIZE Painter::Measure(const std::wstring& s, HFONT font) {
    SIZE sz{0, 0};
    HGDIOBJ old = SelectObject(m_dc, font);
    GetTextExtentPoint32W(m_dc, s.c_str(), (int)s.size(), &sz);
    SelectObject(m_dc, old);
    return sz;
}

int Painter::MeasureWrapped(const std::wstring& s, HFONT font, int width, UINT format) {
    if (s.empty() || width <= 0) return 0;
    RECT r = { 0, 0, width, 0 };
    HGDIOBJ old = SelectObject(m_dc, font);
    DrawTextW(m_dc, s.c_str(), (int)s.size(), &r, format | DT_CALCRECT);
    SelectObject(m_dc, old);
    return r.bottom - r.top;
}

}
