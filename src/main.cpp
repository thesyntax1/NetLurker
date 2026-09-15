#include "ui_layout.h"
#include "common.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include "netmon.h"
#include "geo.h"
#include "threat.h"
#include "cert.h"
#include "banner.h"
#include "firewall.h"
#include "dns.h"
#include "wifi.h"
#include "ai.h"
#include "history.h"
#include "i18n.h"
#include "plugins.h"
#include "ui_draw.h"
#include "json.h"
#include "resource.h"

#include <commctrl.h>
#include <commdlg.h>
#include <shellapi.h>
#include <dwmapi.h>
#include <windowsx.h>
#include "settings_dialog.h"
#include "config_store.h"
#include "http_url.h"
#include <mutex>
#include <thread>
#include <memory>
#include <atomic>
#include <sstream>
#include <cwchar>
#include <ctime>

using namespace nl;

#define WM_APP_AI_DONE (WM_APP + 11)
#define WM_APP_TRAY    (WM_APP + 12)

enum : int {
    ID_FILTER_ALL = 100, ID_FILTER_ACTIVE, ID_FILTER_LISTEN, ID_FILTER_SUSPECT,
    ID_FILTER_TCP, ID_FILTER_UDP, ID_FILTER_EXTERNAL, ID_FILTER_UNSIGNED,
    ID_FILTER_HTTPS, ID_FILTER_UNKNOWN, ID_FILTER_RECENT, ID_FILTER_END,
    ID_TAB_CONNS = 200, ID_TAB_APPS, ID_TAB_HIST, ID_TAB_STATS, ID_TAB_GRAPH,
    ID_BTN_PAUSE = 300, ID_BTN_REFRESH, ID_BTN_AI, ID_BTN_EXPORT, ID_BTN_SETTINGS, ID_BTN_DETAIL, ID_BTN_DEMO_EXIT,
    ID_BTN_KILL, ID_BTN_SUSPEND, ID_BTN_BLOCK,
    ID_EDIT_SEARCH = 400,
    IDM_COPY_IP = 500, IDM_COPY_ROW, IDM_OPEN_FOLDER, IDM_KILL, IDM_AI, IDM_BLOCK_IP, IDM_WHOIS,
    IDM_AI_BULK, IDM_COPY_PATH, IDM_COPY_CMD, IDM_FILTER_PROC, IDM_FILTER_IP,
    IDM_KILL_TREE, IDM_SUSPEND, IDM_COPY_HASH, IDM_VT_FILE, IDM_PROPERTIES, IDM_COPY_ALL,
    IDM_THREAT_REFRESH, IDM_CERT_REFRESH, IDM_ABUSE_OPEN, IDM_CIRCL_OPEN,
    IDM_UNBLOCK_IP,
    IDM_TRAY_SHOW = 600, IDM_TRAY_PAUSE, IDM_TRAY_EXIT
};

enum class Filter { All, Active, Listening, Suspicious, Tcp, Udp, External, Unsigned_, Https, UnknownProc, Recent };
enum class Tab    { Conns, Apps, History, Stats, Graph };
enum class Overlay { None, Welcome, Privacy };

struct Column {
    int          id;
    const wchar_t* title;
    int          minW;
    int          weight;
    int          priority;
    UINT         align;
    bool         mono;
};

enum { C_PROC = 0, C_PUB, C_SIGN, C_PID, C_PROTO, C_LOCAL, C_REMOTE, C_PORTSVC, C_STATE,
       C_GEO, C_CITY, C_ORG, C_ASN, C_HOST, C_DOMAIN, C_BANNER, C_MODULE, C_THREAT, C_CERT,
       C_RTT, C_DOWN, C_UP, C_TOTAL, C_AGE, C_RISK };
static Column kConnCols[] = {
    { C_PROC,   L"Application",     150, 3, 1, DT_LEFT,  false },
    { C_PUB,    L"Publisher",      120, 2, 5, DT_LEFT,  false },
    { C_SIGN,   L"Signature",          72, 0, 6, DT_LEFT,  false },
    { C_PID,    L"PID",           54, 0, 7, DT_RIGHT, false },
    { C_PROTO,  L"Proto",         54, 0, 4, DT_LEFT,  false },
    { C_LOCAL,  L"Local address",  132, 1, 8, DT_LEFT,  true  },
    { C_REMOTE, L"Remote address",  158, 2, 1, DT_LEFT,  true  },
    { C_PORTSVC,L"Service",        90, 0, 5, DT_LEFT,  false },
    { C_STATE,  L"Status",         98, 0, 6, DT_LEFT,  false },
    { C_GEO,    L"Country",         112, 1, 2, DT_LEFT,  false },
    { C_CITY,   L"City",        104, 1, 9, DT_LEFT,  false },
    { C_ORG,    L"Organization", 132, 2, 3, DT_LEFT,  false },
    { C_ASN,    L"ASN",          110, 1, 9, DT_LEFT,  false },
    { C_HOST,   L"Host (rDNS)",  140, 2, 7, DT_LEFT,  false },
    { C_DOMAIN, L"Domain",     150, 2, 4, DT_LEFT,  false },
    { C_BANNER, L"Banner",       110, 1, 9, DT_LEFT,  false },
    { C_MODULE, L"Module (DLL)",  110, 1, 8, DT_LEFT,  false },
    { C_THREAT, L"Threat",        96, 0, 6, DT_LEFT,  false },
    { C_CERT,   L"Certificate",    150, 2, 9, DT_LEFT,  false },
    { C_RTT,    L"RTT",           56, 0, 8, DT_RIGHT, false },
    { C_DOWN,   L"Download",       80, 0, 2, DT_RIGHT, false },
    { C_UP,     L"Upload",       80, 0, 2, DT_RIGHT, false },
    { C_TOTAL,  L"Total",        84, 0, 6, DT_RIGHT, false },
    { C_AGE,    L"Age",          64, 0, 8, DT_RIGHT, false },
    { C_RISK,   L"Risk",          88, 0, 1, DT_LEFT,  false },
};

enum { A_PROC = 0, A_PUB, A_SIGN, A_PID, A_USER, A_SVC, A_CONNS, A_REMOTE, A_DOWN, A_UP,
       A_TOTAL, A_CPU, A_RAM, A_IO, A_THREADS, A_UPTIME, A_COUNTRIES, A_RISK, A_PATH,
       A_DOMAIN };
static Column kAppCols[] = {
    { A_PROC,      L"Application",   150, 2, 1, DT_LEFT,  false },
    { A_PUB,       L"Publisher",    130, 2, 3, DT_LEFT,  false },
    { A_SIGN,      L"Signature",        72, 0, 4, DT_LEFT,  false },
    { A_PID,       L"PID",         54, 0, 6, DT_RIGHT, false },
    { A_USER,      L"User",  120, 1, 7, DT_LEFT,  false },
    { A_SVC,       L"Service",     120, 1, 8, DT_LEFT,  false },
    { A_CONNS,     L"Connection",    76, 0, 2, DT_RIGHT, false },
    { A_REMOTE,    L"Internet",    76, 0, 2, DT_RIGHT, false },
    { A_DOWN,      L"Download",     86, 0, 1, DT_RIGHT, false },
    { A_UP,        L"Upload",     86, 0, 1, DT_RIGHT, false },
    { A_TOTAL,     L"Total",      86, 0, 5, DT_RIGHT, false },
    { A_CPU,       L"CPU",         62, 0, 2, DT_RIGHT, false },
    { A_RAM,       L"Memory",      80, 0, 3, DT_RIGHT, false },
    { A_IO,        L"Disk I/O",    92, 0, 7, DT_RIGHT, false },
    { A_THREADS,   L"Threads",    70, 0, 8, DT_RIGHT, false },
    { A_UPTIME,    L"Uptime",     84, 0, 6, DT_RIGHT, false },
    { A_COUNTRIES, L"Countries",    110, 1, 5, DT_LEFT,  false },
    { A_RISK,      L"Risk",        88, 0, 1, DT_LEFT,  false },
    { A_PATH,      L"Path",        200, 4, 9, DT_LEFT,  false },
    { A_DOMAIN,    L"Domain",   130, 1, 8, DT_LEFT,  false },
};

enum { H_TIME = 0, H_PROC, H_PROTO, H_REMOTE, H_SVC, H_GEO, H_ORG, H_HOST, H_DOMAIN, H_BANNER,
       H_MODULE, H_THREAT, H_IN, H_OUT, H_DUR, H_STATE, H_RISK };
static Column kHistCols[] = {
    { H_TIME,   L"Start",   80, 0, 1, DT_LEFT,  false },
    { H_PROC,   L"Application",   140, 2, 1, DT_LEFT,  false },
    { H_PROTO,  L"Proto",       54, 0, 5, DT_LEFT,  false },
    { H_REMOTE, L"Destination",      160, 2, 1, DT_LEFT,  true  },
    { H_SVC,    L"Service",      90, 0, 4, DT_LEFT,  false },
    { H_GEO,    L"Country",       112, 1, 2, DT_LEFT,  false },
    { H_ORG,    L"Organization",130, 2, 3, DT_LEFT,  false },
    { H_HOST,   L"Host",       140, 2, 6, DT_LEFT,  false },
    { H_DOMAIN, L"Domain",   140, 2, 5, DT_LEFT,  false },
    { H_BANNER, L"Banner",     110, 1, 9, DT_LEFT,  false },
    { H_MODULE, L"Module",      110, 1, 9, DT_LEFT,  false },
    { H_THREAT, L"Threat",      96, 0, 7, DT_LEFT,  false },
    { H_IN,     L"Downloaded",   86, 0, 3, DT_RIGHT, false },
    { H_OUT,    L"Uploaded",  86, 0, 3, DT_RIGHT, false },
    { H_DUR,    L"Age",        84, 0, 4, DT_RIGHT, false },
    { H_STATE,  L"Status",       74, 0, 2, DT_LEFT,  false },
    { H_RISK,   L"Risk",        88, 0, 1, DT_LEFT,  false },
};

struct AppRow {
    DWORD pid = 0;
    std::wstring name, path, publisher, user, services, cmdline, product, version;
    SignState sign = SignState::Unknown;
    int conns = 0, publicConns = 0, listenPorts = 0;
    double rateIn = 0, rateOut = 0;
    unsigned long long bytesIn = 0, bytesOut = 0;
    Risk risk = Risk::Safe;
    int  riskScore = 0;
    std::wstring riskReason;
    std::wstring countries;
    std::wstring domain;
    std::vector<std::wstring> domains;
    unsigned long long startTime = 0;

    double cpu = 0.0;
    unsigned long long ram = 0, ioRead = 0, ioWrite = 0;
    double ioRate = 0.0;
    unsigned long threads = 0, handles = 0;
    bool suspended = false, elevated = false;
    Integrity integrity = Integrity::Unknown;
    std::wstring UptimeText() const {
        if (!startTime) return L"—";
        unsigned long long now = (unsigned long long)time(nullptr) * 1000ull;
        if (now <= startTime) return FormatDurationShort(0);
        return FormatDurationShort((now - startTime) / 1000ull);
    }
    std::wstring SignText() const {
        switch (sign) {
            case SignState::SignedMicrosoft: return Tr(L"Microsoft");
            case SignState::Signed:          return Tr(L"Signed");
            case SignState::Unsigned:        return Tr(L"UNSIGNED");
            case SignState::Invalid:         return Tr(L"INVALID");
            case SignState::Missing:         return Tr(L"no file");
            case SignState::Checking:        return Tr(L"…");
            default:                         return L"—";
        }
    }
};

struct Button {
    int  id = 0;
    RECT rc{0,0,0,0};
    std::wstring label;
    bool toggle = false;
    bool active = false;
    bool primary = false;
    bool danger  = false;
    bool enabled = true;
    bool visible = true;
};

struct Query {
    std::wstring text;
    std::wstring proc, ip, org, country, host, user, module, cert;
    int  port = -1;
    int  minRisk = -1;
    int  minThreat = -1;
    bool empty = true;
};

static Query ParseQuery(const std::wstring& raw) {
    Query q;
    if (Trim(raw).empty()) return q;
    q.empty = false;
    std::wistringstream ss(raw);
    std::wstring tok;
    while (ss >> tok) {
        size_t c = tok.find(L':');
        if (c == std::wstring::npos || c + 1 >= tok.size()) {
            if (!q.text.empty()) q.text += L" ";
            q.text += tok;
            continue;
        }
        std::wstring k = ToLower(tok.substr(0, c));
        std::wstring v = tok.substr(c + 1);
        if      (k == L"proc" || k == L"app" || k == L"exe") q.proc = v;
        else if (k == L"ip"   || k == L"dst")                q.ip = v;
        else if (k == L"org"  || k == L"isp")                q.org = v;
        else if (k == L"country" || k == L"cc")              q.country = v;
        else if (k == L"host" || k == L"dns")                q.host = v;
        else if (k == L"user")                               q.user = v;
        else if (k == L"module" || k == L"dll")              q.module = v;
        else if (k == L"cert")                               q.cert = v;
        else if (k == L"port") q.port = _wtoi(v.c_str());
        else if (k == L"risk") {
            std::wstring num = v;
            if (!num.empty() && (num[0] == L'>' || num[0] == L'<' || num[0] == L'=')) num = num.substr(1);
            if (!num.empty() && num[0] == L'=') num = num.substr(1);
            q.minRisk = _wtoi(num.c_str());
        } else if (k == L"threat" || k == L"abuse") {
            std::wstring num = v;
            if (!num.empty() && (num[0] == L'>' || num[0] == L'<' || num[0] == L'=')) num = num.substr(1);
            if (!num.empty() && num[0] == L'=') num = num.substr(1);
            q.minThreat = _wtoi(num.c_str());
        } else {
            if (!q.text.empty()) q.text += L" ";
            q.text += tok;
        }
    }
    return q;
}

static bool HostMatchesCert(const std::wstring& host, const std::wstring& cn,
                            const std::wstring& sans) {
    if (host.empty() || host == L"—") return true;
    std::wstring h = ToLower(Trim(host));
    while (!h.empty() && h.back() == L'.') h.pop_back();
    if (h.empty() || h.find(L'.') == std::wstring::npos) return true;

    auto domainEq = [&](const std::wstring& raw) {
        std::wstring n = ToLower(Trim(raw));
        while (!n.empty() && n.back() == L'.') n.pop_back();
        if (n.empty()) return false;
        return n == h ||
               (n.size() > h.size() && n.substr(n.size() - h.size() - 1) == L"." + h) ||
               (h.size() > n.size() && h.substr(h.size() - n.size() - 1) == L"." + n);
    };
    if (domainEq(cn)) return true;
    size_t p = 0;
    while (p <= sans.size()) {
        size_t q = sans.find(L',', p);
        std::wstring one = Trim(sans.substr(p, q == std::wstring::npos ? std::wstring::npos : q - p));
        if (domainEq(one)) return true;
        if (q == std::wstring::npos) break;
        p = q + 1;
    }
    return false;
}

struct FwState {
    std::mutex m;
    std::unordered_set<std::wstring> ips;
    std::unordered_map<std::wstring, std::wstring> names;
    bool checked = false;
    std::atomic<bool> busy{ false };
};

class App {
public:
    bool Init(HINSTANCE hInst, int nCmdShow);
    static LRESULT CALLBACK WndProcStatic(HWND, UINT, WPARAM, LPARAM);

private:

    HINSTANCE m_inst = nullptr;
    HWND  m_hwnd   = nullptr;
    HWND  m_search = nullptr;
    WNDPROC m_searchOldProc = nullptr;
    int   m_dpi = 96;
    HFONT m_fUi = nullptr, m_fBold = nullptr, m_fTitle = nullptr, m_fSmall = nullptr,
          m_fMono = nullptr, m_fSmallBold = nullptr, m_fBig = nullptr, m_fHuge = nullptr;
    HBRUSH m_brSurface = nullptr;
    NOTIFYICONDATAW m_nid{};
    bool  m_trayAdded = false;

    NetMonitor     m_mon;
    GeoResolver    m_geo;
    ThreatResolver m_threat;
    CertResolver   m_cert;
    BannerResolver m_banner;
    DnsCacheService m_dns;
    History        m_hist;
    std::vector<Conn>   m_rows;
    std::vector<AppRow> m_apps;
    std::vector<int>    m_view;
    struct RateSample { unsigned long long ts = 0; double in = 0, out = 0; };
    std::deque<RateSample> m_rateHist;
    static constexpr unsigned long long kRateWindowMs = 300000;

    Tab     m_tab       = Tab::Conns;
    Filter  m_filter    = Filter::All;
    std::wstring m_searchText;
    Query   m_query;
    int     m_sortCol   = C_DOWN,  m_sortDir = -1;
    int     m_appSortCol = A_DOWN, m_appSortDir = -1;
    int     m_histSortCol = H_TIME, m_histSortDir = -1;
    int     m_scrollY   = 0;
    int     m_hoverRow  = -1;
    int     m_selRow    = -1;
    std::wstring m_selKey;
    DWORD   m_selPid    = 0;
    bool    m_paused    = false;
    bool    m_showDetail = true;
    std::wstring m_lang = L"en";
    bool    m_geoOnline  = true;
    bool    m_threatOnline = true;
    bool    m_rdapOnline  = true;
    bool    m_vtOnline    = false;
    bool    m_bannerOnline = true;
    bool    m_wifiLoaded = false;
    WifiInfo m_wifi{};
    std::wstring m_abuseKey;
    std::wstring m_vtKey;
    bool    m_notify     = true;
    bool    m_soundAlert = false;
    int     m_notifyMin  = 70;
    bool    m_confirmKill = false;
    int     m_winX = -32000, m_winY = -32000, m_winW = 0, m_winH = 0;
    bool    m_winMax = false;
    int     m_interval   = 1000;
    unsigned long long m_lastWifiTick = 0;
    int     m_hotBtn     = -1;
    int     m_hotCol     = -1;
    bool    m_dragScroll = false;
    int     m_dragOffset = 0;
    bool    m_isAdmin    = false;
    unsigned long long m_startedAt = 0;
    unsigned long long m_lastRefreshTs = 0;
    unsigned           m_lastTickCostMs = 0;
    bool               m_aiKeyMissing   = false;
    std::shared_ptr<FwState> m_fw = std::make_shared<FwState>();
    std::unordered_set<std::wstring> m_blockedIps;
    unsigned long long m_lastFwTick = 0;
    bool               m_fwChecked  = false;
    int                m_effInterval    = 0;
    std::unordered_map<std::wstring, bool> m_alerted;
    std::wstring       m_toast;
    COLORREF           m_toastColor = 0;
    unsigned long long m_toastUntil = 0;

    std::mutex   m_aiMtx;
    std::wstring m_aiText;
    bool         m_aiBusy = false;
    int          m_aiScroll = 0;
    int          m_aiMaxScroll = 0;
    std::wstring m_aiTitle;
    std::wstring m_lastAiPrompt;
    std::wstring m_lastAiProc;
    RECT         m_aiBtn1{}, m_aiBtn2{}, m_aiBtn3{};

    std::vector<Button> m_buttons;
    RECT m_rcHeader{}, m_rcToolbar{}, m_rcTable{}, m_rcTableHead{}, m_rcRows{},
         m_rcDetail{}, m_rcStatus{}, m_rcScroll{}, m_rcSearch{}, m_rcDemoExit{};
    std::vector<int> m_colX, m_colW;
    std::vector<int> m_visCols;

    int S(int v) const { return MulDiv(v, m_dpi, 96); }
    int RowH() const   { return S(28); }
    bool IsTableTab() const { return m_tab != Tab::Stats && m_tab != Tab::Graph; }
    const Column* Cols() const {
        switch (m_tab) {
            case Tab::Apps:    return kAppCols;
            case Tab::History: return kHistCols;
            default:           return kConnCols;
        }
    }
    int ColCount() const {
        switch (m_tab) {
            case Tab::Apps:    return (int)(sizeof(kAppCols)  / sizeof(kAppCols[0]));
            case Tab::History: return (int)(sizeof(kHistCols) / sizeof(kHistCols[0]));
            default:           return (int)(sizeof(kConnCols) / sizeof(kConnCols[0]));
        }
    }
    int& SortCol() {
        switch (m_tab) {
            case Tab::Apps:    return m_appSortCol;
            case Tab::History: return m_histSortCol;
            default:           return m_sortCol;
        }
    }
    int& SortDir() {
        switch (m_tab) {
            case Tab::Apps:    return m_appSortDir;
            case Tab::History: return m_histSortDir;
            default:           return m_sortDir;
        }
    }

    void CreateFonts();
    void DestroyFonts();
    void ApplyDarkTitleBar();
    void Layout();
    void ComputeColumns();
    void LoadPrefs();
    void SavePrefs();
    void SetupTray();
    void RemoveTray();
    void Notify(const std::wstring& title, const std::wstring& text, bool warning);

    void Tick(bool force);
    void RebuildApps();
    void RebuildView();
    void CheckAlerts();
    std::wstring CellText(const Conn& c, int col) const;
    std::wstring AppCellText(const AppRow& a, int col) const;
    std::wstring HistCellText(const HistEntry& h, int col) const;
    const Conn*      SelectedConn() const;
    const AppRow*    SelectedApp() const;
    const HistEntry* SelectedHist() const;
    bool  Matches(const Conn& c) const;

    void OnPaint();
    void DrawHelp(Painter& p);
    bool m_showHelp = false;
    void DrawGraph(Painter& p);
    void DrawOverlay(Painter& p);
    void DrawHeader(Painter&);
    void DrawToolbar(Painter&);
    void DrawTable(Painter&);
    void DrawStats(Painter&);
    void DrawDetail(Painter&);
    void DrawStatus(Painter&);
    void DrawButton(Painter&, const Button&);
    void DrawSparkline(Painter&, RECT area);
    void DrawBadge(Painter&, RECT r, const std::wstring& text, COLORREF fg, COLORREF bg);
    void DrawBarList(Painter&, RECT area, const std::wstring& title,
                     const std::vector<CountItem>& items, COLORREF accent, bool bytes);
    void DrawMiniGraph(Painter&, RECT area, const RateHistory* rh, bool measurable);
    void DrawRiskCell(Painter&, RECT cr, Risk risk, int score, const std::wstring& label);

    Overlay m_overlay = Overlay::None;
    bool    m_overlayDrawn = false;
    RECT    m_ovBtn1{}, m_ovBtn2{}, m_ovBtn3{};
    void ShowOverlay(Overlay o);
    void DrawOverlayButton(Painter& p, RECT& r, const std::wstring& label, bool primary, bool danger);
    bool m_demo = false;
    void EnterDemo();
    void ExitDemo();
    void RebuildDemoRows();
    void RebuildDemoApps();
    void FollowUpAi(int q);
    std::vector<Conn> m_demoRows;
    unsigned long long m_lastDemoTick = 0;

    struct AnomStat { double ema = 0; double var = 0; int n = 0; double lastRate = 0; };
    struct AnomAlert { std::wstring name; double baseline = 0; double current = 0; int pct = 0;
                       unsigned long long t = 0; unsigned long long warned = 0; };
    std::unordered_map<std::wstring, AnomStat>  m_anomStats;
    std::unordered_map<std::wstring, int>       m_anomNew;
    std::unordered_map<std::wstring, AnomAlert> m_anomAlerts;
    std::vector<std::pair<std::wstring, double>> m_anomRates;
    unsigned long long m_lastAnomTick = 0;
    void TickAnomaly();
    void LoadAnomalyBaseline();
    void SaveAnomalyBaseline();
    void NoteNewConnections();
    void PushRateSample(double in, double out);
    void RefreshFirewallRules(bool force);
    void UnblockSelectedIp();

    void OnLButtonDown(int x, int y);
    void OnLButtonUp(int x, int y);
    void OnMouseMove(int x, int y);
    void OnMouseWheel(int delta, POINT pt);
    void OnKeyDown(WPARAM key);
    void OnCommand(int id);
    void OnContextMenu(int x, int y);
    void OnAiDone(bool ok, std::wstring* text);
    void OnTray(LPARAM lp);

    void SetSelection(int viewIndex);
    void EnsureVisible();
    int  RowAt(int y) const;
    int  MaxScroll() const;
    int  TotalRows() const { return (int)m_view.size(); }
    void SetSearch(const std::wstring& text);

    void RunAiAnalysis(bool bulk = false);
    void ExportData();
    void KillSelectedProcess(bool tree);
    void SuspendSelectedProcess();
    void ShowProcessProperties();
    void Toast(const std::wstring& msg, COLORREF color);
    DWORD SelectedPid(std::wstring* nameOut = nullptr) const;
    void BlockSelectedIp();
    void CopyToClipboard(const std::wstring& text);
    void ShowSettings();
    void Relaunch(bool asAdmin);

    LRESULT WndProc(HWND, UINT, WPARAM, LPARAM);
    static LRESULT CALLBACK SearchProc(HWND, UINT, WPARAM, LPARAM);
    static INT_PTR CALLBACK ElevateProc(HWND, UINT, WPARAM, LPARAM);

    static INT_PTR CALLBACK SettingsProc(HWND, UINT, WPARAM, LPARAM);
};

static App* g_app = nullptr;

struct ScopedTimerPause {
    HWND hwnd; UINT id; int interval;
    ScopedTimerPause(HWND h, UINT i, int iv) : hwnd(h), id(i), interval(iv) { KillTimer(hwnd, id); }
    ~ScopedTimerPause() { SetTimer(hwnd, id, interval, nullptr); }
};

void App::CreateFonts() {
    DestroyFonts();
    auto mk = [&](int pt, int weight, const wchar_t* face) {
        return CreateFontW(-MulDiv(pt, m_dpi, 72), 0, 0, 0, weight, FALSE, FALSE, FALSE,
                           DEFAULT_CHARSET, OUT_TT_PRECIS, CLIP_DEFAULT_PRECIS,
                           CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, face);
    };
    m_fUi        = mk(9,  FW_NORMAL,   L"Segoe UI");
    m_fBold      = mk(9,  FW_SEMIBOLD, L"Segoe UI");
    m_fSmall     = mk(8,  FW_NORMAL,   L"Segoe UI");
    m_fSmallBold = mk(8,  FW_SEMIBOLD, L"Segoe UI");
    m_fTitle     = mk(15, FW_BOLD,     L"Segoe UI");
    m_fBig       = mk(11, FW_SEMIBOLD, L"Segoe UI");
    m_fHuge      = mk(20, FW_BOLD,     L"Segoe UI");
    m_fMono      = mk(9,  FW_NORMAL,   L"Consolas");
    if (!m_fMono) m_fMono = mk(9, FW_NORMAL, L"Courier New");
}

void App::DestroyFonts() {
    HFONT* fonts[] = { &m_fUi, &m_fBold, &m_fTitle, &m_fSmall, &m_fMono, &m_fSmallBold,
                       &m_fBig, &m_fHuge };
    for (auto f : fonts) if (*f) { DeleteObject(*f); *f = nullptr; }
}

void App::ApplyDarkTitleBar() {
    BOOL dark = TRUE;
    DwmSetWindowAttribute(m_hwnd, 20, &dark, sizeof(dark));
    DwmSetWindowAttribute(m_hwnd, 19, &dark, sizeof(dark));
}

void App::LoadPrefs() {
    const std::wstring p = ConfigPath();
    m_geoOnline  = GetPrivateProfileIntW(L"ui", L"geo",       1, p.c_str()) != 0;
    m_threatOnline = GetPrivateProfileIntW(L"ui", L"threat",  1, p.c_str()) != 0;
    m_rdapOnline   = GetPrivateProfileIntW(L"ui", L"rdap",    1, p.c_str()) != 0;
    m_bannerOnline = GetPrivateProfileIntW(L"ui", L"banner",  1, p.c_str()) != 0;
    wchar_t lkey[64] = L"";
    GetPrivateProfileStringW(L"ui", L"lang", L"en", lkey, 64, p.c_str());
    m_lang = Trim(lkey);
    const auto languages = I18nLanguages();
    if (std::none_of(languages.begin(), languages.end(),
                     [&](const auto& l) { return l.first == m_lang; })) m_lang = L"en";
    wchar_t akey[1024] = L"";
    GetPrivateProfileStringW(L"threat", L"abusekey", L"", akey, 1024, p.c_str());
    m_abuseKey = Trim(akey);
    wchar_t vkey[1024] = L"";
    GetPrivateProfileStringW(L"threat", L"vtkey", L"", vkey, 1024, p.c_str());
    m_vtKey = Trim(vkey);
    m_vtOnline = !m_vtKey.empty();
    m_notify     = GetPrivateProfileIntW(L"ui", L"notify",    1, p.c_str()) != 0;
    m_soundAlert = GetPrivateProfileIntW(L"ui", L"sound",     0, p.c_str()) != 0;
    m_notifyMin  = GetPrivateProfileIntW(L"ui", L"notifymin", 70, p.c_str());
    m_interval   = GetPrivateProfileIntW(L"ui", L"interval",  1000, p.c_str());
    m_confirmKill= GetPrivateProfileIntW(L"ui", L"confirmkill", 0, p.c_str()) != 0;
    m_showDetail = GetPrivateProfileIntW(L"ui", L"detail",     1, p.c_str()) != 0;
    int tab      = GetPrivateProfileIntW(L"ui", L"tab",        0, p.c_str());
    if (tab >= 0 && tab <= 4) m_tab = (Tab)tab;
    int flt      = GetPrivateProfileIntW(L"ui", L"filter",     0, p.c_str());
    if (flt >= 0 && flt < (int)Filter::Recent + 1) m_filter = (Filter)flt;
    m_sortCol    = GetPrivateProfileIntW(L"ui", L"sortcol", C_DOWN, p.c_str());
    m_sortDir    = GetPrivateProfileIntW(L"ui", L"sortdir", -1, p.c_str()) >= 0 ? 1 : -1;

    const int schema = GetPrivateProfileIntW(L"ui", L"sortcols", 3, p.c_str());
    if (schema < 5) {
        if (schema < 4) {
            if (m_sortCol >= 14 && m_sortCol <= 19) m_sortCol += 5;
        } else {
            if (m_sortCol >= 14 && m_sortCol <= 22) m_sortCol += 2;
        }
    }
    if (m_sortCol < 0 || m_sortCol >= (int)(sizeof(kConnCols)/sizeof(kConnCols[0]))) m_sortCol = C_DOWN;
    m_appSortCol = GetPrivateProfileIntW(L"ui", L"appsortcol", A_DOWN, p.c_str());
    if (m_appSortCol < 0 || m_appSortCol >= (int)(sizeof(kAppCols)/sizeof(kAppCols[0]))) m_appSortCol = A_DOWN;
    m_winW       = GetPrivateProfileIntW(L"win", L"w", 0, p.c_str());
    m_winH       = GetPrivateProfileIntW(L"win", L"h", 0, p.c_str());
    m_winX       = GetPrivateProfileIntW(L"win", L"x", -32000, p.c_str());
    m_winY       = GetPrivateProfileIntW(L"win", L"y", -32000, p.c_str());
    m_winMax     = GetPrivateProfileIntW(L"win", L"max", 0, p.c_str()) != 0;
    if (m_interval < 500)   m_interval = 500;
    if (m_interval > 10000) m_interval = 10000;
    if (m_notifyMin < 20)   m_notifyMin = 20;
    if (m_notifyMin > 100)  m_notifyMin = 100;
}

void App::SavePrefs() {
    const std::wstring p = ConfigPath();
    std::vector<IniValue> values;
    auto put = [&](const wchar_t* k, int v) {
        values.push_back({L"ui", k, std::to_wstring(v)});
    };
    put(L"geo", m_geoOnline ? 1 : 0);
    values.push_back({L"ui", L"lang", m_lang});
    put(L"threat", m_threatOnline ? 1 : 0);
    put(L"rdap", m_rdapOnline ? 1 : 0);
    put(L"banner", m_bannerOnline ? 1 : 0);
    put(L"sortcols", 5);
    values.push_back({L"threat", L"abusekey", m_abuseKey});
    values.push_back({L"threat", L"vtkey", m_vtKey});
    put(L"notify", m_notify ? 1 : 0);
    put(L"sound", m_soundAlert ? 1 : 0);
    put(L"notifymin", m_notifyMin);
    put(L"interval", m_interval);
    put(L"confirmkill", m_confirmKill ? 1 : 0);
    put(L"detail", m_showDetail ? 1 : 0);
    put(L"tab", (int)m_tab);
    put(L"filter", (int)m_filter);
    put(L"sortcol", m_sortCol);
    put(L"sortdir", m_sortDir);
    put(L"appsortcol", m_appSortCol);

    if (m_hwnd) {
        WINDOWPLACEMENT wp;
        wp.length = sizeof(wp);
        if (GetWindowPlacement(m_hwnd, &wp)) {
            auto putw = [&](const wchar_t* k, int v) {
                values.push_back({L"win", k, std::to_wstring(v)});
            };
            const RECT& n = wp.rcNormalPosition;
            putw(L"x", n.left);
            putw(L"y", n.top);
            putw(L"w", n.right - n.left);
            putw(L"h", n.bottom - n.top);
            putw(L"max", (wp.showCmd == SW_SHOWMAXIMIZED) ? 1 : 0);
        }
    }
    UpdateIniAtomically(p, values);
}

void App::SetupTray() {
    ZeroMemory(&m_nid, sizeof(m_nid));
    m_nid.cbSize = sizeof(m_nid);
    m_nid.hWnd   = m_hwnd;
    m_nid.uID    = 1;
    m_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    m_nid.uCallbackMessage = WM_APP_TRAY;
    m_nid.hIcon  = LoadIconW(m_inst, MAKEINTRESOURCEW(IDI_APPICON));
    if (!m_nid.hIcon) m_nid.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    wcsncpy_s(m_nid.szTip, Tr(L"NetLurker — network monitor"), _TRUNCATE);
    m_trayAdded = Shell_NotifyIconW(NIM_ADD, &m_nid) == TRUE;
}

void App::RemoveTray() {
    if (m_trayAdded) {
        Shell_NotifyIconW(NIM_DELETE, &m_nid);
        m_trayAdded = false;
    }
}

void App::Notify(const std::wstring& title, const std::wstring& text, bool warning) {
    if (!m_trayAdded) return;
    NOTIFYICONDATAW n = m_nid;
    n.uFlags = NIF_INFO;
    n.dwInfoFlags = warning ? NIIF_WARNING : NIIF_INFO;
    wcsncpy_s(n.szInfoTitle, title.c_str(), _TRUNCATE);
    wcsncpy_s(n.szInfo, text.c_str(), _TRUNCATE);
    Shell_NotifyIconW(NIM_MODIFY, &n);
    if (m_soundAlert && warning) MessageBeep(MB_ICONWARNING);
}

bool App::Init(HINSTANCE hInst, int nCmdShow) {
    m_inst = hInst;
    m_isAdmin = IsRunAsAdmin();
    m_startedAt = NowMs();
    LoadPrefs();
    m_aiKeyMissing = LoadAiConfig().apiKey.empty();

    I18nSetLanguage(m_lang);
    I18nLoadFrom(ExeDir() + L"\\lang");
    I18nLoadFrom(AppDataDir() + L"\\lang");
    PluginsLoadFrom(ExeDir() + L"\\plugins");
    PluginsLoadFrom(AppDataDir() + L"\\plugins");

    WNDCLASSEXW wc;
    ZeroMemory(&wc, sizeof(wc));
    wc.cbSize        = sizeof(wc);
    wc.style         = CS_HREDRAW | CS_VREDRAW | CS_DBLCLKS;
    wc.lpfnWndProc   = &App::WndProcStatic;
    wc.hInstance     = hInst;
    wc.hCursor       = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = nullptr;
    wc.lpszClassName = L"NetLurkerMainWnd";
    wc.hIcon         = LoadIconW(hInst, MAKEINTRESOURCEW(IDI_APPICON));
    wc.hIconSm       = wc.hIcon;
    if (!RegisterClassExW(&wc)) return false;

    int sw = GetSystemMetrics(SM_CXSCREEN), sh = GetSystemMetrics(SM_CYSCREEN);
    int w = (std::min)(1560, (int)(sw * 0.88));
    int h = (std::min)(940,  (int)(sh * 0.88));
    int x = (sw - w) / 2, y = (sh - h) / 2;
    if (m_winW > 400 && m_winH > 300) {
        w = m_winW; h = m_winH;

        RECT want = { m_winX, m_winY, m_winX + w, m_winY + h };
        if (m_winX > -32000 && MonitorFromRect(&want, MONITOR_DEFAULTTONULL)) { x = m_winX; y = m_winY; }
    }

    m_hwnd = CreateWindowExW(0, wc.lpszClassName, Tr(L"NetLurker — Network & Process Monitor"),
                             WS_OVERLAPPEDWINDOW, x, y, w, h,
                             nullptr, nullptr, hInst, this);
    if (!m_hwnd) return false;

    ApplyDarkTitleBar();
    ShowWindow(m_hwnd, m_winMax ? SW_SHOWMAXIMIZED : nCmdShow);
    UpdateWindow(m_hwnd);
    return true;
}

void App::Layout() {
    RECT rc;
    GetClientRect(m_hwnd, &rc);
    const int W = rc.right, H = rc.bottom;

    // The navigation gets its own row; it must not compete with live rates.
    m_rcHeader = { 0, 0, W, S(102) };
    m_buttons.clear();
    const int pad = S(12), gap = S(6), bh = S(28);
    const int available = (std::max)(1, W - 2 * pad);
    std::vector<int> widths;

    struct ChipDef { int id; const wchar_t* txt; Filter f; };
    const ChipDef chips[] = {
        { ID_FILTER_ALL,      Tr(L"All"),      Filter::All },
        { ID_FILTER_ACTIVE,   Tr(L"Connected"),     Filter::Active },
        { ID_FILTER_EXTERNAL, Tr(L"Internet"),  Filter::External },
        { ID_FILTER_LISTEN,   Tr(L"Listening"),  Filter::Listening },
        { ID_FILTER_SUSPECT,  Tr(L"Suspicious"),   Filter::Suspicious },
        { ID_FILTER_UNSIGNED, Tr(L"Unsigned"),   Filter::Unsigned_ },
        { ID_FILTER_HTTPS,    Tr(L"HTTPS"),     Filter::Https },
        { ID_FILTER_UNKNOWN,  Tr(L"Unknown"),Filter::UnknownProc },
        { ID_FILTER_RECENT,   Tr(L"New"),      Filter::Recent },
        { ID_FILTER_TCP,      Tr(L"TCP"),       Filter::Tcp },
        { ID_FILTER_UDP,      Tr(L"UDP"),       Filter::Udp },
    };

    HDC hdc = GetDC(m_hwnd);
    auto textW = [&](const std::wstring& s, HFONT f) {
        SIZE sz{0,0};
        HGDIOBJ o = SelectObject(hdc, f);
        GetTextExtentPoint32W(hdc, s.c_str(), (int)s.size(), &sz);
        SelectObject(hdc, o);
        return (int)sz.cx;
    };

    for (const auto& c : chips) {
        Button b;
        b.id     = c.id;
        b.label  = c.txt;
        b.toggle = true;
        b.active = (m_filter == c.f);
        int w = textW(b.label, m_fBold) + S(20);
        widths.push_back(w);
        m_buttons.push_back(b);
    }

    const size_t searchIndex = widths.size();
    widths.push_back(S(180));
    struct ActDef { int id; const wchar_t* txt; bool primary; bool toggle; bool active; bool danger; };
    const bool haveProc = (SelectedPid() != 0);
    std::wstring selRemote;
    if (const Conn* sc = SelectedConn())           { if (sc->isRemotePublic) selRemote = sc->remoteIp; }
    else if (const HistEntry* sh = SelectedHist()) selRemote = sh->remoteIp;
    const bool blockedSel = !selRemote.empty() && m_blockedIps.count(selRemote) != 0;
    const ActDef acts[] = {
        { ID_BTN_SETTINGS, Tr(L"Settings"),   false, false, false, false },
        { ID_BTN_EXPORT,   Tr(L"Export"),false, false, false, false },
        { ID_BTN_DETAIL,   Tr(L"Details"),     false, true,  m_showDetail, false },
        { ID_BTN_PAUSE,    m_paused ? Tr(L"Resume") : Tr(L"Pause"), false, true, m_paused, false },
        { ID_BTN_KILL,     Tr(L"⨯ Kill"), false, false, false, true },
        { ID_BTN_BLOCK,    blockedSel ? Tr(L"⛔ Unblock IP") : Tr(L"⛔ Block IP"),
                           false, true, blockedSel, !blockedSel },
        { ID_BTN_AI,       Tr(L"AI Analyze"), true,  false, false, false },
    };
    for (const auto& a : acts) {
        Button b;
        b.id      = a.id;
        b.label   = a.txt;
        b.primary = a.primary;
        b.toggle  = a.toggle;
        b.active  = a.active;
        b.danger  = a.danger;
        if (a.id == ID_BTN_KILL) b.enabled = haveProc;
        if (a.id == ID_BTN_BLOCK) b.enabled = !selRemote.empty();
        int w = textW(b.label, m_fBold) + S(22);
        widths.push_back(w);
        m_buttons.push_back(b);
    }

    // Grow the search field only when everything fits on one row. Otherwise wrap
    // every control (including all filters), rather than hiding or overlapping it.
    int fixedWidth = gap * (int)(widths.size() - 1);
    for (size_t i = 0; i < widths.size(); ++i)
        if (i != searchIndex) fixedWidth += widths[i];
    widths[searchIndex] = (std::max)(S(180), (std::min)(S(420), available - fixedWidth));
    const auto flow = PackToolbar(widths, available, bh, gap);
    size_t buttonIndex = 0;
    for (size_t i = 0; i < flow.items.size(); ++i) {
        const auto& item = flow.items[i];
        const int left = pad + item.x, top = m_rcHeader.bottom + S(9) + item.y;
        RECT bounds = { left, top, left + item.width, top + item.height };
        if (i == searchIndex) m_rcSearch = bounds;
        else m_buttons[buttonIndex++].rc = bounds;
    }
    m_rcToolbar = { 0, m_rcHeader.bottom, W, m_rcHeader.bottom + flow.height + S(18) };
    m_rcStatus = { 0, (std::max)(0, H - S(28)), W, H };
    const int contentH = (std::max)(0, (int)m_rcStatus.top - (int)m_rcToolbar.bottom);
    const int detailH = (m_showDetail && IsTableTab())
        ? (std::min)((std::max)(0, contentH - S(100)),
                     (std::max)(S(160), (std::min)(S(300), (int)(H * 0.31)))) : 0;
    m_rcDetail = { 0, m_rcStatus.top - detailH, W, m_rcStatus.top };
    m_rcTable = { 0, m_rcToolbar.bottom, W, (std::max)(m_rcToolbar.bottom, m_rcDetail.top) };
    m_rcTableHead = { 0, m_rcTable.top, W, (std::min)(m_rcTable.bottom, m_rcTable.top + S(32)) };
    m_rcRows = { 0, m_rcTableHead.bottom, W, m_rcTable.bottom };
    m_rcScroll = { W - S(10), m_rcRows.top, W, m_rcRows.bottom };
    ReleaseDC(m_hwnd, hdc);

    if (m_search) {
        MoveWindow(m_search, m_rcSearch.left + S(28), m_rcSearch.top + S(4),
                   (m_rcSearch.right - m_rcSearch.left) - S(36),
                   (m_rcSearch.bottom - m_rcSearch.top) - S(8), TRUE);
        SendMessageW(m_search, WM_SETFONT, (WPARAM)m_fUi, TRUE);
    }

    ComputeColumns();
}

void App::ComputeColumns() {
    if (!IsTableTab()) { m_visCols.clear(); m_colX.clear(); m_colW.clear(); return; }
    const Column* cols = Cols();
    const int n = ColCount();
    const int avail = (m_rcRows.right - m_rcRows.left) - S(24) - S(12);

    std::vector<int> use;
    for (int i = 0; i < n; ++i) use.push_back(i);
    auto totalMin = [&]() {
        int t = 0;
        for (int i : use) t += S(cols[i].minW);
        return t;
    };
    for (int prio = 9; prio >= 2 && totalMin() > avail; --prio) {
        for (size_t k = use.size(); k-- > 0;) {
            if (cols[use[k]].priority == prio) {
                use.erase(use.begin() + k);
                if (totalMin() <= avail) break;
            }
        }
    }

    int extra = avail - totalMin();
    int wsum = 0;
    for (int i : use) wsum += cols[i].weight;

    m_visCols = use;
    m_colW.assign(use.size(), 0);
    m_colX.assign(use.size(), 0);
    int x = m_rcRows.left + S(12);
    for (size_t k = 0; k < use.size(); ++k) {
        int w = S(cols[use[k]].minW);
        if (extra > 0 && wsum > 0 && cols[use[k]].weight > 0)
            w += MulDiv(extra, cols[use[k]].weight, wsum);
        m_colX[k] = x;
        m_colW[k] = w;
        x += w;
    }
}

void App::Tick(bool force) {
    if (m_paused && !force) return;
    const unsigned long long tickStart = NowMs();
    m_lastRefreshTs = tickStart;
    struct TickTimer {
        App* self; unsigned long long t0;
        ~TickTimer() { self->m_lastTickCostMs = (unsigned)(NowMs() - t0); }
    } tickTimer{ this, tickStart };

    if (m_demo) {
        RebuildDemoRows();
        m_rows = m_demoRows;
        RebuildDemoApps();
        NoteNewConnections();
        TickAnomaly();
        PushRateSample(m_mon.SystemRateIn(), m_mon.SystemRateOut());
        RebuildView();
        return;
    }

    m_mon.Refresh();
    m_rows = m_mon.Connections();

    for (auto& c : m_rows) {
        if (!c.isRemotePublic) {
            if (c.IsListening())              { c.country = L"—";             c.org = Tr(L"listening"); }
            else if (c.remotePort)            { c.country = Tr(L"Local network"); c.org = L"—"; }
            else                              { c.country = L"—";        c.org = L"—"; }
            c.host = L"—";
            continue;
        }
        GeoInfo g;
        if (m_geo.Get(c.remoteIp, g, m_geoOnline)) {
            c.country     = g.country;
            c.countryCode = g.countryCode;
            c.city        = g.city;
            c.region      = g.region;
            c.org         = g.org;
            c.asn         = g.asn;
            c.asname      = g.asname;
            c.host        = g.host;
            c.isHosting   = g.hosting;
            c.isProxy     = g.proxy;
            c.isMobile    = g.mobile;
            c.geoPending  = !g.resolved;
            c.geoTs       = g.ts;
            if (c.geoPending && c.country.empty()) c.country = Tr(L"querying…");
            if (g.resolved && g.failed && c.org.empty()) c.org = Tr(L"(unknown owner)");
        } else if (m_geoOnline) {
            c.geoPending = true;
            c.country = Tr(L"querying…");
            c.org = L"—";
            c.host = L"—";
        } else {
            c.country = Tr(L"(geolocation off)");
            c.org = L"—";
            c.host = L"—";
        }
    }

    const bool threatEnq = m_threatOnline || m_rdapOnline || m_vtOnline;
    for (auto& c : m_rows) {
        if (!c.isRemotePublic) continue;
        ThreatInfo t;
        if (m_threat.Get(c.remoteIp, t, threatEnq)) {
            c.threatScore      = t.abuseScore;
            c.threatReports    = t.totalReports;
            c.threatLastReport = t.lastReport;
            c.threatTor        = t.isTor;
            c.threatDnsbl      = t.dnsbl;
            c.threatDnsblIncomplete = t.dnsblIncomplete;
            c.threatPdns       = t.passiveDns;
            c.threatPdnsNames  = t.pdnsNames;
            c.threatPending    = !t.resolved;
            c.threatTs         = t.ts;
            c.rdapName         = t.rdapName;
            c.rdapOrg          = t.rdapOrg;
            c.rdapAbuse        = t.rdapAbuse;
            c.rdapCidr         = t.rdapCidr;
            c.rdapRegistered   = t.rdapRegistered;
            c.vtMalicious      = t.vtMalicious;
            c.vtSuspicious     = t.vtSuspicious;
            c.vtTotal          = t.vtTotal;
            c.vtReputation     = t.vtReputation;

            if (t.pluginRisk >= 0) {
                if (c.threatScore < 0 || t.pluginRisk > c.threatScore)
                    c.threatScore = t.pluginRisk;
                c.pluginNote = t.pluginVerdict;
                if (!t.pluginNote.empty())
                    c.pluginNote += L" — " + t.pluginNote;
            }
        } else if (threatEnq) {
            c.threatPending = true;
        }
    }

    m_dns.Refresh();
    for (auto& c : m_rows) {
        if (!c.isRemotePublic) continue;
        const std::wstring d = m_dns.DomainFor(c.remoteIp);
        if (!d.empty()) c.domain = d;
        c.hostsRedirect = m_dns.IsHostsRedirect(c.remoteIp);
    }

    for (auto& c : m_rows) {
        if (!c.isRemotePublic || !c.IsTcp() || c.state != MIB_TCP_STATE_ESTAB) continue;
        const bool webPort = c.remotePort == 80   || c.remotePort == 8080 ||
                             c.remotePort == 8000 || c.remotePort == 8888;
        if (!webPort) continue;
        BannerInfo bi;
        const std::wstring key = c.remoteIp + L":" + std::to_wstring(c.remotePort);
        if (m_banner.Get(key, bi, m_bannerOnline)) {
            c.banner         = bi.server;
            c.bannerStatus   = bi.status;
            c.bannerPending  = !bi.resolved;
            c.bannerTs       = bi.ts;
        } else if (m_bannerOnline) {
            c.bannerPending = true;
        }
    }

    if (GetTickCount64() - m_lastWifiTick >= 15000) {
        m_lastWifiTick = GetTickCount64();
        m_wifi = QueryWifi();
        m_wifiLoaded = true;
    }

    for (auto& c : m_rows) {
        if (!c.isRemotePublic || !c.IsTcp() || c.state != MIB_TCP_STATE_ESTAB) continue;
        const bool tlsPort = c.remotePort == 443  || c.remotePort == 8443 || c.remotePort == 4443 ||
                             c.remotePort == 853  || c.remotePort == 465  || c.remotePort == 636  ||
                             c.remotePort == 993  || c.remotePort == 995;
        if (!tlsPort) continue;
        CertInfo ci;
        std::wstring key = c.remoteIp + L":" + std::to_wstring(c.remotePort);

        std::wstring sni;
        if (!c.host.empty() && c.host != L"—" && !c.geoPending)
            sni = c.host;
        if (m_cert.Get(key, ci, m_threatOnline, sni)) {
            c.certIssuer      = ci.issuer;
            c.certSubject     = ci.subject;
            c.certSans        = ci.sans;
            c.certThumbprint  = ci.thumbprint;
            c.certVersion     = ci.version;
            c.certNotAfter    = ci.notAfter;
            c.certSelfSigned  = ci.selfSigned;
            c.certExpired     = ci.expired;
            c.certNotYetValid = ci.notYetValid;
            c.certPending     = false;
            c.certTs          = ci.ts;
            if (ci.ok && !ci.subject.empty())
                c.certMismatch = !HostMatchesCert(c.host, ci.subject, ci.sans);
        } else if (m_threatOnline) {
            c.certPending = true;
        }
    }

    {
        std::unordered_map<DWORD, int> distinct;
        std::unordered_map<DWORD, std::vector<std::wstring>> ips;
        for (const auto& c : m_rows) {
            if (!c.isRemotePublic) continue;
            auto& v = ips[c.pid];
            if (std::find(v.begin(), v.end(), c.remoteIp) == v.end()) v.push_back(c.remoteIp);
        }
        for (auto& kv : ips) distinct[kv.first] = (int)kv.second.size();
        for (auto& c : m_rows) {
            RiskContext ctx;
            ctx.nowMs = NowMs();
            auto it = distinct.find(c.pid);
            ctx.distinctRemotes = (it == distinct.end()) ? 0 : it->second;
            EvaluateRisk(c, ctx);
            if (!c.pluginNote.empty())
                c.riskReason += std::wstring(L" • ") + Tr(L"Plugin") + L": " + c.pluginNote;
        }
    }

    RefreshFirewallRules(false);
    for (auto& c : m_rows)
        if (!c.remoteIp.empty() && m_blockedIps.count(c.remoteIp)) c.fwBlocked = true;

    m_hist.Update(m_rows);
    RebuildApps();
    NoteNewConnections();
    TickAnomaly();
    CheckAlerts();

    PushRateSample(m_mon.SystemRateIn(), m_mon.SystemRateOut());

    RebuildView();
}

void App::CheckAlerts() {
    if (!m_notify) return;

    for (const auto& ev : m_mon.PortScanEvents()) {
        const std::wstring key = L"scan|" + std::to_wstring(ev.port) + L"|" +
                                 std::to_wstring(ev.t);
        if (m_alerted.count(key)) continue;
        m_alerted[key] = true;
        m_hist.NoteAlert();
        std::wstring body = Tr(L"Your local port ") + std::to_wstring(ev.port) + Tr(L" is being scanned from the outside ") +
                            std::to_wstring(ev.count) + Tr(L" by a different IP.") +
                            Tr(L"Sample source: ") + ev.sample;
        Notify(Tr(L"NetLurker: inbound port scan"), body, true);
        break;
    }
    for (const auto& c : m_rows) {

        const bool dnsblBad = !c.threatDnsbl.empty() && c.threatDnsbl != L"—";
        if (c.riskScore < m_notifyMin && !dnsblBad) continue;
        const std::wstring key = c.procName + L"|" + c.remoteIp + L"|" + std::to_wstring(c.remotePort);
        if (m_alerted.count(key)) continue;
        m_alerted[key] = true;
        m_hist.NoteAlert();
        std::wstring body = c.procName + L" → " + c.RemoteText();
        if (!c.country.empty() && c.country[0] != L'(') body += L"  (" + c.country + L")";
        if (dnsblBad && c.riskScore < m_notifyMin)
            body += std::wstring(L"\n") + Tr(L"Destination IP is blacklisted: ") + c.threatDnsbl;
        else
            body += L"\n" + c.riskReason;
        if (body.size() > 240) body = body.substr(0, 237) + L"…";
        std::wstring title = dnsblBad ? Tr(L"NetLurker: connection to blacklisted IP")
                                      : Tr(L"NetLurker: risky connection (") + std::to_wstring(c.riskScore) + L"/100)";
        Notify(title, body, true);
        break;
    }
    if (m_alerted.size() > 2000) m_alerted.clear();
}

void App::RebuildApps() {
    std::vector<AppRow> apps;
    apps.reserve(96);
    for (const auto& c : m_rows) {
        AppRow* row = nullptr;
        for (auto& a : apps) if (a.pid == c.pid) { row = &a; break; }
        if (!row) {
            apps.push_back(AppRow{});
            row = &apps.back();
            ProcDetails d = m_mon.Procs().Get(c.pid);
            row->pid       = c.pid;
            row->name      = d.DisplayName();
            row->path      = d.path;
            row->publisher = d.Publisher();
            row->user      = d.user;
            row->services  = d.services;
            row->cmdline   = d.cmdline;
            row->product   = d.product;
            row->version   = d.fileVersion;
            row->sign      = d.sign;
            row->startTime = d.startTime;
            row->elevated  = d.elevated;
            row->integrity = d.integrity;
            ProcRuntime rt = m_mon.Procs().Runtime(c.pid);
            row->cpu       = rt.cpu;
            row->ram       = rt.workingSet;
            row->ioRead    = rt.ioRead;
            row->ioWrite   = rt.ioWrite;
            row->ioRate    = rt.ioReadRate + rt.ioWriteRate;
            row->threads   = rt.threads;
            row->handles   = rt.handles;
            row->suspended = rt.suspended;
        }
        row->conns++;
        if (c.isRemotePublic) row->publicConns++;
        if (c.IsListening())  row->listenPorts++;
        row->rateIn   += c.rateIn;
        row->rateOut  += c.rateOut;
        row->bytesIn  += c.bytesIn;
        row->bytesOut += c.bytesOut;
        if (c.riskScore > row->riskScore) {
            row->riskScore  = c.riskScore;
            row->risk       = c.risk;
            row->riskReason = c.riskReason;
        }
        if (!c.countryCode.empty() && row->countries.find(c.countryCode) == std::wstring::npos) {
            if (!row->countries.empty()) row->countries += L" ";
            if (row->countries.size() < 40) row->countries += c.countryCode;
        }
        if (!c.domain.empty() && c.domain != L"—" &&
            std::find(row->domains.begin(), row->domains.end(), c.domain) == row->domains.end() &&
            row->domains.size() < 8)
            row->domains.push_back(c.domain);
    }
    for (auto& a : apps) {

        if (a.domain.empty() && !a.domains.empty()) {
            a.domain = a.domains[0];
            if (a.domains.size() > 1) a.domain += L" +" + std::to_wstring(a.domains.size() - 1);
        }
    }
    m_apps.swap(apps);
}

static int CompareText(const std::wstring& a, const std::wstring& b) {
    return _wcsicmp(a.c_str(), b.c_str());
}

bool App::Matches(const Conn& c) const {
    const Query& q = m_query;
    if (q.empty) return true;
    if (!q.proc.empty()    && !Contains(c.procName + L" " + c.procPath, q.proc)) return false;
    if (!q.ip.empty()      && !Contains(c.remoteIp + L" " + c.localIp, q.ip)) return false;
    if (!q.org.empty()     && !Contains(c.org + L" " + c.asn + L" " + c.asname, q.org)) return false;
    if (!q.country.empty() && !Contains(c.country + L" " + c.countryCode + L" " + c.city, q.country)) return false;
    if (!q.host.empty()    && !Contains(c.host, q.host)) return false;
    if (!q.user.empty()    && !Contains(c.user, q.user)) return false;
    if (!q.module.empty()  && !Contains(c.module, q.module)) return false;
    if (!q.cert.empty()    && !Contains(c.certIssuer + L" " + c.certSubject + L" " + c.certSans,
                                        q.cert)) return false;
    if (q.port >= 0 && c.remotePort != q.port && c.localPort != q.port) return false;
    if (q.minRisk >= 0 && c.riskScore < q.minRisk) return false;
    if (q.minThreat >= 0 && c.threatScore < q.minThreat) return false;
    if (!q.text.empty()) {
        std::wstring hay = c.procName + L" " + c.procPath + L" " + c.publisher + L" " +
                           c.LocalText() + L" " + c.RemoteText() + L" " + c.country + L" " +
                           c.city + L" " + c.org + L" " + c.asn + L" " + c.host + L" " +
                           c.module + L" " + c.certIssuer + L" " + c.certSubject + L" " +
                           c.threatDnsbl + L" " + c.domain + L" " + c.banner + L" " +
                           c.rdapOrg + L" " + c.rdapAbuse + L" " +
                           c.StateText() + L" " + c.services + L" " + std::to_wstring(c.pid);
        if (!Contains(hay, q.text)) return false;
    }
    return true;
}

void App::RebuildView() {
    m_view.clear();
    if (m_tab == Tab::Graph) return;

    if (m_tab == Tab::Conns) {
        for (int i = 0; i < (int)m_rows.size(); ++i) {
            const Conn& c = m_rows[i];
            bool pass = true;
            switch (m_filter) {
                case Filter::Active:     pass = (c.state == MIB_TCP_STATE_ESTAB) || (!c.IsTcp() && !c.IsListening()); break;
                case Filter::Listening:  pass = c.IsListening(); break;
                case Filter::Suspicious: pass = ((int)c.risk >= (int)Risk::Warn); break;
                case Filter::Tcp:        pass = c.IsTcp(); break;
                case Filter::Udp:        pass = !c.IsTcp(); break;
                case Filter::External:   pass = c.isRemotePublic; break;
                case Filter::Unsigned_:  pass = (c.sign == SignState::Unsigned ||
                                                 c.sign == SignState::Invalid  ||
                                                 c.sign == SignState::Missing); break;
                case Filter::Https:      pass = (c.remotePort == 443 || c.remotePort == 8443); break;
                case Filter::UnknownProc:pass = (c.procName.empty() || c.procPath.empty() ||
                                                 (c.sign != SignState::Signed && c.publisher.empty())); break;
                case Filter::Recent:     pass = (c.ageMs < 60000); break;
                default: break;
            }
            if (pass) pass = Matches(c);
            if (pass) m_view.push_back(i);
        }

        const int col = m_sortCol, dir = m_sortDir;
        std::stable_sort(m_view.begin(), m_view.end(), [&](int ia, int ib) {
            const Conn& a = m_rows[ia];
            const Conn& b = m_rows[ib];
            int r = 0;
            auto cmpNum = [](double x, double y) { return x < y ? -1 : (x > y ? 1 : 0); };
            switch (col) {
                case C_PROC:   r = CompareText(a.procName, b.procName); break;
                case C_PUB:    r = CompareText(a.publisher, b.publisher); break;
                case C_SIGN:   r = cmpNum((double)(int)a.sign, (double)(int)b.sign); break;
                case C_PID:    r = cmpNum((double)a.pid, (double)b.pid); break;
                case C_PROTO:  r = CompareText(a.ProtoText(), b.ProtoText()); break;
                case C_LOCAL:  r = cmpNum(a.localPort, b.localPort); break;
                case C_REMOTE: r = CompareText(a.remoteIp, b.remoteIp);
                               if (!r) r = cmpNum(a.remotePort, b.remotePort); break;
                case C_PORTSVC:r = cmpNum(a.remotePort, b.remotePort); break;
                case C_STATE:  r = CompareText(a.StateText(), b.StateText()); break;
                case C_GEO:    r = CompareText(a.country, b.country); break;
                case C_CITY:   r = CompareText(a.city, b.city); break;
                case C_ORG:    r = CompareText(a.org, b.org); break;
                case C_ASN:    r = CompareText(a.asn, b.asn); break;
                case C_HOST:   r = CompareText(a.host, b.host); break;
                case C_DOMAIN: r = CompareText(a.domain, b.domain); break;
                case C_BANNER: r = CompareText(a.banner, b.banner); break;
                case C_MODULE: r = CompareText(a.module, b.module); break;
                case C_THREAT: r = cmpNum((double)a.threatScore, (double)b.threatScore); break;
                case C_CERT:   r = CompareText(a.certIssuer, b.certIssuer); break;
                case C_RTT:    r = cmpNum(a.rttMs, b.rttMs); break;
                case C_DOWN:   r = cmpNum(a.rateIn, b.rateIn); break;
                case C_UP:     r = cmpNum(a.rateOut, b.rateOut); break;
                case C_TOTAL:  r = cmpNum((double)(a.bytesIn + a.bytesOut), (double)(b.bytesIn + b.bytesOut)); break;
                case C_AGE:    r = cmpNum((double)a.ageMs, (double)b.ageMs); break;
                case C_RISK:   r = cmpNum(a.riskScore, b.riskScore); break;
            }
            if (r == 0) r = CompareText(a.procName, b.procName);
            return dir < 0 ? (r > 0) : (r < 0);
        });
    } else if (m_tab == Tab::Apps) {
        for (int i = 0; i < (int)m_apps.size(); ++i) {
            const AppRow& a = m_apps[i];
            bool pass = true;
            if (m_filter == Filter::Suspicious) pass = ((int)a.risk >= (int)Risk::Warn);
            if (m_filter == Filter::External)   pass = a.publicConns > 0;
            if (m_filter == Filter::Listening)  pass = a.listenPorts > 0;
            if (m_filter == Filter::Unsigned_)  pass = (a.sign == SignState::Unsigned ||
                                                        a.sign == SignState::Invalid  ||
                                                        a.sign == SignState::Missing);
            if (pass && !m_query.empty) {
                std::wstring hay = a.name + L" " + a.path + L" " + a.publisher + L" " +
                                   a.user + L" " + a.services + L" " + a.domain + L" " +
                                   std::to_wstring(a.pid);
                if (!m_query.text.empty()  && !Contains(hay, m_query.text)) pass = false;
                if (!m_query.proc.empty()  && !Contains(a.name + L" " + a.path, m_query.proc)) pass = false;
                if (!m_query.user.empty()  && !Contains(a.user, m_query.user)) pass = false;
                if (m_query.minRisk >= 0   && a.riskScore < m_query.minRisk) pass = false;
            }
            if (pass) m_view.push_back(i);
        }
        const int col = m_appSortCol, dir = m_appSortDir;
        std::stable_sort(m_view.begin(), m_view.end(), [&](int ia, int ib) {
            const AppRow& a = m_apps[ia];
            const AppRow& b = m_apps[ib];
            auto cmpNum = [](double x, double y) { return x < y ? -1 : (x > y ? 1 : 0); };
            int r = 0;
            switch (col) {
                case A_PROC:      r = CompareText(a.name, b.name); break;
                case A_PUB:       r = CompareText(a.publisher, b.publisher); break;
                case A_SIGN:      r = cmpNum((double)(int)a.sign, (double)(int)b.sign); break;
                case A_PID:       r = cmpNum((double)a.pid, (double)b.pid); break;
                case A_USER:      r = CompareText(a.user, b.user); break;
                case A_SVC:       r = CompareText(a.services, b.services); break;
                case A_CONNS:     r = cmpNum(a.conns, b.conns); break;
                case A_REMOTE:    r = cmpNum(a.publicConns, b.publicConns); break;
                case A_DOWN:      r = cmpNum(a.rateIn, b.rateIn); break;
                case A_UP:        r = cmpNum(a.rateOut, b.rateOut); break;
                case A_TOTAL:     r = cmpNum((double)(a.bytesIn + a.bytesOut), (double)(b.bytesIn + b.bytesOut)); break;
                case A_CPU:       r = cmpNum(a.cpu, b.cpu); break;
                case A_RAM:       r = cmpNum((double)a.ram, (double)b.ram); break;
                case A_IO:        r = cmpNum(a.ioRate, b.ioRate); break;
                case A_THREADS:   r = cmpNum((double)a.threads, (double)b.threads); break;
                case A_UPTIME:    r = cmpNum((double)b.startTime, (double)a.startTime); break;
                case A_COUNTRIES: r = CompareText(a.countries, b.countries); break;
                case A_RISK:      r = cmpNum(a.riskScore, b.riskScore); break;
                case A_PATH:      r = CompareText(a.path, b.path); break;
                case A_DOMAIN:    r = CompareText(a.domain, b.domain); break;
            }
            if (r == 0) r = CompareText(a.name, b.name);
            return dir < 0 ? (r > 0) : (r < 0);
        });
    } else if (m_tab == Tab::History) {
        const auto& ents = m_hist.Entries();
        for (int i = 0; i < (int)ents.size(); ++i) {
            const HistEntry& h = ents[i];
            bool pass = true;
            if (m_filter == Filter::Suspicious) pass = ((int)h.risk >= (int)Risk::Warn);
            if (m_filter == Filter::Active)     pass = h.active;
            if (m_filter == Filter::Https)      pass = (h.remotePort == 443 || h.remotePort == 8443);
            if (m_filter == Filter::UnknownProc) pass = h.path.empty();
            if (m_filter == Filter::Recent)     pass = (h.firstSeen && NowMs() - h.firstSeen < 60000);
            if (pass && !m_query.empty) {
            std::wstring hay = h.proc + L" " + h.remoteIp + L" " + h.country + L" " +
                               h.org + L" " + h.host + L" " + h.module + L" " +
                               h.certIssuer + L" " + h.threatDnsbl + L" " +
                               h.domain + L" " + h.banner + L" " +
                               std::to_wstring(h.remotePort);
                if (!m_query.text.empty()    && !Contains(hay, m_query.text)) pass = false;
                if (!m_query.proc.empty()    && !Contains(h.proc, m_query.proc)) pass = false;
                if (!m_query.ip.empty()      && !Contains(h.remoteIp, m_query.ip)) pass = false;
                if (!m_query.country.empty() && !Contains(h.country + L" " + h.countryCode, m_query.country)) pass = false;
                if (!m_query.org.empty()     && !Contains(h.org, m_query.org)) pass = false;
                if (!m_query.module.empty()  && !Contains(h.module, m_query.module)) pass = false;
                if (m_query.port >= 0        && h.remotePort != m_query.port) pass = false;
                if (m_query.minRisk >= 0     && h.riskScore < m_query.minRisk) pass = false;
                if (m_query.minThreat >= 0   && h.threatScore < m_query.minThreat) pass = false;
            }
            if (pass) m_view.push_back(i);
        }
        const int col = m_histSortCol, dir = m_histSortDir;
        std::stable_sort(m_view.begin(), m_view.end(), [&](int ia, int ib) {
            const HistEntry& a = ents[ia];
            const HistEntry& b = ents[ib];
            auto cmpNum = [](double x, double y) { return x < y ? -1 : (x > y ? 1 : 0); };
            int r = 0;
            switch (col) {
                case H_TIME:   r = cmpNum((double)a.firstSeen, (double)b.firstSeen); break;
                case H_PROC:   r = CompareText(a.proc, b.proc); break;
                case H_PROTO:  r = CompareText(a.proto, b.proto); break;
                case H_REMOTE: r = CompareText(a.remoteIp, b.remoteIp); break;
                case H_SVC:    r = cmpNum(a.remotePort, b.remotePort); break;
                case H_GEO:    r = CompareText(a.country, b.country); break;
                case H_ORG:    r = CompareText(a.org, b.org); break;
                case H_HOST:   r = CompareText(a.host, b.host); break;
                case H_DOMAIN: r = CompareText(a.domain, b.domain); break;
                case H_BANNER: r = CompareText(a.banner, b.banner); break;
                case H_MODULE: r = CompareText(a.module, b.module); break;
                case H_THREAT: r = cmpNum((double)a.threatScore, (double)b.threatScore); break;
                case H_IN:     r = cmpNum((double)a.bytesIn, (double)b.bytesIn); break;
                case H_OUT:    r = cmpNum((double)a.bytesOut, (double)b.bytesOut); break;
                case H_DUR:    r = cmpNum((double)a.DurationMs(), (double)b.DurationMs()); break;
                case H_STATE:  r = cmpNum(a.active ? 1 : 0, b.active ? 1 : 0); break;
                case H_RISK:   r = cmpNum(a.riskScore, b.riskScore); break;
            }
            if (r == 0) r = cmpNum((double)a.firstSeen, (double)b.firstSeen);
            return dir < 0 ? (r > 0) : (r < 0);
        });
    }

    m_selRow = -1;
    if (m_tab == Tab::Conns && !m_selKey.empty()) {
        for (int i = 0; i < (int)m_view.size(); ++i)
            if (m_rows[m_view[i]].Key() == m_selKey) { m_selRow = i; break; }
    } else if (m_tab == Tab::Apps && m_selPid) {
        for (int i = 0; i < (int)m_view.size(); ++i)
            if (m_apps[m_view[i]].pid == m_selPid) { m_selRow = i; break; }
    } else if (m_tab == Tab::History && !m_selKey.empty()) {
        const auto& ents = m_hist.Entries();
        for (int i = 0; i < (int)m_view.size(); ++i)
            if (ents[m_view[i]].key == m_selKey) { m_selRow = i; break; }
    }

    const int maxS = MaxScroll();
    if (m_scrollY > maxS) m_scrollY = maxS;
    if (m_scrollY < 0) m_scrollY = 0;
}

std::wstring App::CellText(const Conn& c, int col) const {
    wchar_t buf[160];
    switch (col) {
        case C_PROC:   return c.services.empty() ? c.procName : (c.procName + L" (" + c.services + L")");
        case C_PUB:    return c.publisher;
        case C_SIGN:
            switch (c.sign) {
                case SignState::SignedMicrosoft: return Tr(L"Microsoft");
                case SignState::Signed:          return Tr(L"Signed");
                case SignState::Unsigned:        return Tr(L"UNSIGNED");
                case SignState::Invalid:         return Tr(L"INVALID");
                case SignState::Missing:         return Tr(L"no file");
                case SignState::Checking:        return Tr(L"…");
                default:                         return L"—";
            }
        case C_PID:    return std::to_wstring(c.pid);
        case C_PROTO:  return c.ProtoText();
        case C_LOCAL:  return c.LocalText();
        case C_REMOTE: return c.RemoteText();
        case C_PORTSVC: {
            unsigned short p = c.IsListening() ? c.localPort : c.remotePort;
            const wchar_t* s = PortServiceName(p);
            if (s) return s;
            return PortThreatNote(p) ? Tr(L"⚠ risky") : L"—";
        }
        case C_STATE:  return c.fwBlocked ? (L"\u26d4 " + c.StateText()) : c.StateText();
        case C_GEO:
            if (c.countryCode.empty()) return c.country.empty() ? L"—" : c.country;
            swprintf(buf, 160, L"%s  %s", c.countryCode.c_str(), c.country.c_str());
            return buf;
        case C_CITY:   return c.city.empty() ? L"—" : c.city;
        case C_ORG: {
            std::wstring o = c.org.empty() ? L"—" : c.org;
            if (c.isProxy)        o += Tr(L"  [proxy]");
            else if (c.isHosting) o += Tr(L"  [dc]");
            return o;
        }
        case C_ASN:    return c.asn.empty() ? L"—" : c.asn;
        case C_HOST:   return c.host.empty() ? L"—" : c.host;
        case C_DOMAIN: return c.domain.empty() ? L"—" : c.domain;
        case C_BANNER:
            if (c.bannerPending) return Tr(L"querying…");
            if (c.banner.empty()) return L"—";
            return c.banner.size() > 64 ? c.banner.substr(0, 61) + L"…" : c.banner;
        case C_MODULE: return c.module.empty() ? L"—" : c.module;
        case C_THREAT: {
            if (!c.isRemotePublic) return L"—";
            std::wstring s;
            if (c.threatScore >= 0) s = std::to_wstring(c.threatScore) + L"/100";
            else if (c.threatPending) s = Tr(L"querying…");
            if (!c.threatDnsbl.empty() && c.threatDnsbl != L"—") {
                if (!s.empty()) s += L" · ";
                s += c.threatDnsbl;
            }
            if (c.threatTor) {
                if (!s.empty()) s += L" · ";
                s += Tr(L"Tor");
            }
            if (c.vtTotal > 0 && c.vtMalicious > 0) {
                if (!s.empty()) s += L" · ";
                s += L"VT " + std::to_wstring(c.vtMalicious) + L"/" + std::to_wstring(c.vtTotal);
            }
            if (!c.rdapOrg.empty() && c.org.empty()) {
                if (!s.empty()) s += L" · ";
                s += c.rdapOrg;
            }
            return s.empty() ? L"—" : s;
        }
        case C_CERT:
            if (c.certPending) return Tr(L"querying…");
            if (!c.certIssuer.empty()) return c.certIssuer;
            if (!c.certSubject.empty()) return L"CN=" + c.certSubject;
            return L"—";
        case C_RTT:
            if (!c.rttMs) return L"—";
            swprintf(buf, 160, L"%u ms", c.rttMs);
            return buf;

        case C_DOWN:
            if (!c.IsTcp())  return L"n/a";
            if (!m_isAdmin)  return L"n/a";
            return FormatBytesPerSec(c.rateIn);
        case C_UP:
            if (!c.IsTcp())  return L"n/a";
            if (!m_isAdmin)  return L"n/a";
            return FormatBytesPerSec(c.rateOut);
        case C_TOTAL:
            if (!c.bytesIn && !c.bytesOut) return L"—";
            return FormatBytes(c.bytesIn + c.bytesOut);
        case C_AGE:    return c.AgeText();
        case C_RISK:   return c.RiskText();
    }
    return L"";
}

std::wstring App::AppCellText(const AppRow& a, int col) const {
    switch (col) {
        case A_PROC:      return a.name;
        case A_PUB:       return a.publisher;
        case A_SIGN:      return a.SignText();
        case A_PID:       return std::to_wstring(a.pid);
        case A_USER:      return a.user.empty() ? L"—" : a.user;
        case A_SVC:       return a.services.empty() ? L"—" : a.services;
        case A_CONNS:     return std::to_wstring(a.conns);
        case A_REMOTE:    return std::to_wstring(a.publicConns);
        case A_DOWN:      return m_isAdmin ? FormatBytesPerSec(a.rateIn)  : std::wstring(L"n/a");
        case A_UP:        return m_isAdmin ? FormatBytesPerSec(a.rateOut) : std::wstring(L"n/a");
        case A_TOTAL:     return (a.bytesIn + a.bytesOut) ? FormatBytes(a.bytesIn + a.bytesOut)
                                                          : std::wstring(m_isAdmin ? L"—" : L"n/a");
        case A_CPU: {
            if (a.cpu < 0.05) return L"—";
            wchar_t b[24];
            swprintf(b, 24, L"%.1f%%", a.cpu);
            return b;
        }
        case A_RAM:      return a.ram ? FormatBytes(a.ram) : L"—";
        case A_IO:       return a.ioRate > 1.0 ? FormatBytesPerSec(a.ioRate) : L"—";
        case A_THREADS:  return a.threads ? std::to_wstring(a.threads) : L"—";
        case A_UPTIME:   return a.UptimeText();
        case A_COUNTRIES: return a.countries.empty() ? L"—" : a.countries;
        case A_RISK:
            switch (a.risk) {
                case Risk::Danger: return Tr(L"CRITICAL");
                case Risk::Warn:   return Tr(L"SUSPICIOUS");
                case Risk::Info:   return Tr(L"INFO");
                default:           return Tr(L"NORMAL");
            }
        case A_PATH:      return a.path.empty() ? L"—" : a.path;
        case A_DOMAIN:    return a.domain.empty() ? L"—" : a.domain;
    }
    return L"";
}

std::wstring App::HistCellText(const HistEntry& h, int col) const {
    wchar_t buf[160];
    switch (col) {
        case H_TIME:  return h.TimeText();
        case H_PROC:  return h.proc;
        case H_PROTO: return h.proto;
        case H_REMOTE:
            swprintf(buf, 160, L"%s:%u", h.remoteIp.c_str(), (unsigned)h.remotePort);
            return buf;
        case H_SVC: {
            const wchar_t* s = PortServiceName(h.remotePort);
            return s ? s : L"—";
        }
        case H_GEO:
            if (h.countryCode.empty()) return h.country.empty() ? L"—" : h.country;
            swprintf(buf, 160, L"%s  %s", h.countryCode.c_str(), h.country.c_str());
            return buf;
        case H_ORG:   return h.org.empty() ? L"—" : h.org;
        case H_HOST:  return h.host.empty() ? L"—" : h.host;
        case H_DOMAIN:return h.domain.empty() ? L"—" : h.domain;
        case H_BANNER:return h.banner.size() > 64 ? h.banner.substr(0, 61) + L"…"
                                                   : (h.banner.empty() ? L"—" : h.banner);
        case H_MODULE:return h.module.empty() ? L"—" : h.module;
        case H_THREAT: {
            std::wstring s;
            if (h.threatScore >= 0) s = std::to_wstring(h.threatScore) + L"/100";
            if (!h.threatDnsbl.empty() && h.threatDnsbl != L"—") {
                if (!s.empty()) s += L" · ";
                s += h.threatDnsbl;
            }
            return s.empty() ? L"—" : s;
        }
        case H_IN:    return h.bytesIn  ? FormatBytes(h.bytesIn)  : L"—";
        case H_OUT:   return h.bytesOut ? FormatBytes(h.bytesOut) : L"—";
        case H_DUR:   return h.DurationText();
        case H_STATE: return h.active ? Tr(L"open") : Tr(L"closed");
        case H_RISK:
            switch (h.risk) {
                case Risk::Danger: return Tr(L"CRITICAL");
                case Risk::Warn:   return Tr(L"SUSPICIOUS");
                case Risk::Info:   return Tr(L"INFO");
                default:           return Tr(L"NORMAL");
            }
    }
    return L"";
}

const Conn* App::SelectedConn() const {
    if (m_tab != Tab::Conns) return nullptr;
    if (m_selRow < 0 || m_selRow >= (int)m_view.size()) return nullptr;
    int idx = m_view[m_selRow];
    if (idx < 0 || idx >= (int)m_rows.size()) return nullptr;
    return &m_rows[idx];
}

const AppRow* App::SelectedApp() const {
    if (m_tab != Tab::Apps) return nullptr;
    if (m_selRow < 0 || m_selRow >= (int)m_view.size()) return nullptr;
    int idx = m_view[m_selRow];
    if (idx < 0 || idx >= (int)m_apps.size()) return nullptr;
    return &m_apps[idx];
}

const HistEntry* App::SelectedHist() const {
    if (m_tab != Tab::History) return nullptr;
    if (m_selRow < 0 || m_selRow >= (int)m_view.size()) return nullptr;
    const auto& ents = m_hist.Entries();
    int idx = m_view[m_selRow];
    if (idx < 0 || idx >= (int)ents.size()) return nullptr;
    return &ents[idx];
}

static COLORREF RiskColor(Risk r) {
    switch (r) {
        case Risk::Danger: return clr::Red;
        case Risk::Warn:   return clr::Orange;
        case Risk::Info:   return clr::Yellow;
        default:           return clr::Green;
    }
}
static COLORREF RiskBg(Risk r) {
    switch (r) {
        case Risk::Danger: return RGB(60, 24, 24);
        case Risk::Warn:   return RGB(58, 36, 18);
        case Risk::Info:   return RGB(52, 44, 16);
        default:           return clr::Surface;
    }
}
static COLORREF SignColor(SignState s) {
    switch (s) {
        case SignState::SignedMicrosoft: return clr::Cyan;
        case SignState::Signed:          return clr::Green;
        case SignState::Unsigned:        return clr::Orange;
        case SignState::Invalid:
        case SignState::Missing:         return clr::Red;
        default:                         return clr::TextFaint;
    }
}

void App::DrawBadge(Painter& p, RECT r, const std::wstring& text, COLORREF fg, COLORREF bg) {
    p.FillRoundRect(r, S(4), bg);
    p.Text(text, r, m_fSmallBold, fg, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
}

void App::DrawRiskCell(Painter& p, RECT cr, Risk risk, int score, const std::wstring& label) {
    RECT br = cr;
    br.right = (std::min)(cr.right, cr.left + S(62));
    br.top += S(5); br.bottom -= S(5);
    DrawBadge(p, br, label, RiskColor(risk), RiskBg(risk));
    RECT sr = { br.right + S(4), cr.top, (std::min)(cr.right, br.right + S(30)), cr.bottom };
    if (sr.right > sr.left) {
        p.Text(std::to_wstring(score), sr, m_fSmall,
               score >= 45 ? RiskColor(risk) : clr::TextFaint,
               DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    }
}

static std::wstring ClockText(unsigned long long ts, DWORD flags);

void App::DrawSparkline(Painter& p, RECT area) {
    p.FillRoundRect(area, S(6), clr::Surface);
    if (m_rateHist.size() < 2) {
        p.Text(Tr(L"building traffic graph…"), area, m_fSmall, clr::TextFaint,
               DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        return;
    }

    const unsigned long long now  = NowMs();
    const unsigned long long from = (now > kRateWindowMs) ? now - kRateWindowMs : 0;

    double peak = 1024.0;
    for (const auto& sm : m_rateHist) {
        if (sm.ts < from) continue;
        peak = (std::max)(peak, sm.in);
        peak = (std::max)(peak, sm.out);
    }

    const int w  = area.right - area.left - S(8);
    const int h  = area.bottom - area.top - S(8) - S(12);
    const int x0 = area.left + S(4), y0 = area.top + S(4);
    if (w <= 4 || h <= 4) return;

    for (int i = 1; i < 4; ++i) {
        const int gy = y0 + MulDiv(i, h, 4);
        p.Line(x0, gy, x0 + w, gy, clr::Border, 1.0f);
    }

    auto xOf = [&](unsigned long long ts) {
        if (ts <= from) return x0;
        const unsigned long long off = (std::min)(ts - from, kRateWindowMs);
        return x0 + (int)((off * (unsigned long long)w) / kRateWindowMs);
    };
    auto yOf = [&](double v) {
        double f = v / peak;
        if (f < 0.0) f = 0.0;
        if (f > 1.0) f = 1.0;
        return y0 + h - (int)(h * f);
    };

    const unsigned long long gapLimit =
        (std::max)((unsigned long long)m_interval * 3, (unsigned long long)4000);

    std::vector<std::pair<size_t, size_t>> runs;
    size_t runStart = 0;
    std::vector<const RateSample*> vis;
    for (const auto& sm : m_rateHist)
        if (sm.ts >= from) vis.push_back(&sm);
    if (vis.size() < 2) return;
    for (size_t i = 1; i < vis.size(); ++i) {
        if (vis[i]->ts - vis[i - 1]->ts > gapLimit) {
            if (i - runStart >= 2) runs.push_back({ runStart, i - 1 });
            RECT gr = { xOf(vis[i - 1]->ts), y0, xOf(vis[i]->ts), y0 + h };
            if (gr.right > gr.left + 1) p.FillRect(gr, clr::RowAlt);
            runStart = i;
        }
    }
    if (vis.size() - runStart >= 2) runs.push_back({ runStart, vis.size() - 1 });

    auto drawRun = [&](size_t a, size_t b, bool inbound) {
        std::vector<POINT> pts;
        for (size_t i = a; i <= b; ++i)
            pts.push_back(POINT{ xOf(vis[i]->ts), yOf(inbound ? vis[i]->in : vis[i]->out) });
        if (pts.size() < 2) return;
        const COLORREF c = inbound ? clr::Accent : clr::Purple;
        std::vector<POINT> poly = pts;
        poly.push_back(POINT{ pts.back().x, y0 + h });
        poly.push_back(POINT{ pts.front().x, y0 + h });
        p.FillPolygon(poly, c, 48);
        p.Polyline(pts, c, 1.6f);
    };
    for (const auto& rn : runs) { drawRun(rn.first, rn.second, true); drawRun(rn.first, rn.second, false); }

    RECT pr = { x0, y0, x0 + w - S(4), y0 + S(16) };
    p.Text(L"▲ " + FormatBytesPerSec(peak), pr, m_fSmall, clr::TextFaint,
           DT_RIGHT | DT_TOP | DT_SINGLELINE);

    RECT ax = { x0, y0 + h + S(1), x0 + w, area.bottom - S(2) };
    const int mins = (int)(kRateWindowMs / 60000);
    p.Text(L"−" + std::to_wstring(mins) + L":00", ax, m_fSmall, clr::TextFaint,
           DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    p.Text(ClockText(m_rateHist.back().ts / 1000, 0), ax, m_fSmall, clr::TextFaint,
           DT_RIGHT | DT_VCENTER | DT_SINGLELINE);
}

void App::DrawMiniGraph(Painter& p, RECT area, const RateHistory* rh, bool measurable) {
    p.FillRoundRect(area, S(5), clr::RowAlt);
    if (!measurable) {
        p.Text(Tr(L"not measurable (requires administrator rights)"), area, m_fSmall, clr::Yellow,
               DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
        return;
    }
    if (!rh || rh->in.size() < 2 || rh->ts.size() != rh->in.size()) {
        p.Text(Tr(L"collecting data…"), area, m_fSmall, clr::TextFaint,
               DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        return;
    }

    const unsigned long long now  = NowMs();
    const unsigned long long win  = RateHistory::WindowMs;
    const unsigned long long from = (now > win) ? now - win : 0;

    double peak = 1024.0;
    for (size_t i = 0; i < rh->in.size(); ++i) {
        if (rh->ts[i] < from) continue;
        peak = (std::max)(peak, (double)rh->in[i]);
        peak = (std::max)(peak, (double)rh->out[i]);
    }
    const int w = area.right - area.left - S(6);
    const int h = area.bottom - area.top - S(6);
    const int x0 = area.left + S(3), y0 = area.top + S(3);
    if (w <= 4 || h <= 4) return;

    std::vector<size_t> vis;
    for (size_t i = 0; i < rh->in.size(); ++i)
        if (rh->ts[i] >= from) vis.push_back(i);
    if (vis.size() < 2) {
        p.Text(Tr(L"collecting data…"), area, m_fSmall, clr::TextFaint,
               DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        return;
    }

    auto xOf = [&](unsigned long long ts) {
        if (ts <= from) return x0;
        const unsigned long long off = (std::min)(ts - from, win);
        return x0 + (int)((off * (unsigned long long)w) / win);
    };
    auto yOf = [&](double v) {
        double f = v / peak;
        if (f < 0.0) f = 0.0;
        if (f > 1.0) f = 1.0;
        return y0 + h - (int)(h * f);
    };

    const unsigned long long gapLimit =
        (std::max)((unsigned long long)m_interval * 3, (unsigned long long)4000);
    std::vector<std::pair<size_t, size_t>> runs;
    size_t runStart = 0;
    for (size_t k = 1; k < vis.size(); ++k) {
        if (rh->ts[vis[k]] - rh->ts[vis[k - 1]] > gapLimit) {
            if (k - runStart >= 2) runs.push_back({ runStart, k - 1 });
            RECT gr = { xOf(rh->ts[vis[k - 1]]), y0, xOf(rh->ts[vis[k]]), y0 + h };
            if (gr.right > gr.left + 1) p.FillRect(gr, clr::Surface);
            runStart = k;
        }
    }
    if (vis.size() - runStart >= 2) runs.push_back({ runStart, vis.size() - 1 });

    auto drawRun = [&](size_t a, size_t b, bool inbound) {
        std::vector<POINT> pts;
        for (size_t k = a; k <= b; ++k) {
            const size_t i = vis[k];
            pts.push_back(POINT{ xOf(rh->ts[i]), yOf(inbound ? rh->in[i] : rh->out[i]) });
        }
        if (pts.size() < 2) return;
        const COLORREF c = inbound ? clr::Accent : clr::Purple;
        std::vector<POINT> poly = pts;
        poly.push_back(POINT{ pts.back().x, y0 + h });
        poly.push_back(POINT{ pts.front().x, y0 + h });
        p.FillPolygon(poly, c, 44);
        p.Polyline(pts, c, 1.4f);
    };
    for (const auto& rn : runs) { drawRun(rn.first, rn.second, true); drawRun(rn.first, rn.second, false); }
}

void App::DrawHeader(Painter& p) {
    p.FillRect(m_rcHeader, clr::Bg);

    const int pad = S(14);
    int cy = m_rcHeader.top + S(31);
    p.FillCircle(pad + S(10), cy, S(9), clr::AccentDim);
    p.FillCircle(pad + S(10), cy, S(4), clr::Cyan);

    RECT t = { pad + S(26), m_rcHeader.top + S(8), pad + S(300), m_rcHeader.top + S(34) };
    p.Text(L"NetLurker", t, m_fTitle, clr::Text);
    RECT vb = { pad + S(126), m_rcHeader.top + S(13), pad + S(158), m_rcHeader.top + S(29) };
    DrawBadge(p, vb, L"v6", clr::Cyan, clr::SurfaceHi);
    RECT s = { pad + S(28), m_rcHeader.top + S(33), pad + S(360), m_rcHeader.top + S(52) };
    p.Text(Tr(L"process ↔ network connection monitor  •  threat intelligence + TLS certificate analysis"),
           s, m_fSmall, clr::TextDim);

    int tabX = pad;
    struct TabDef { Tab id; int cmd; const wchar_t* txt; };
    const TabDef tabs[] = {
        { Tab::Conns,   ID_TAB_CONNS, Tr(L"Connections") },
        { Tab::Apps,    ID_TAB_APPS,  Tr(L"Apps") },
        { Tab::History, ID_TAB_HIST,  Tr(L"History") },
        { Tab::Stats,   ID_TAB_STATS, Tr(L"Summary") },
        { Tab::Graph,   ID_TAB_GRAPH, Tr(L"Net Graph") },
    };
    for (const auto& td : tabs) {
        std::wstring label = td.txt;
        if (td.id == Tab::History) {
            size_t n = m_hist.Entries().size();
            if (n) label += L" (" + std::to_wstring(n) + L")";
        }
        SIZE sz = p.Measure(label, m_fBold);
        const int maxTabW = (std::max)(1, ((int)m_rcHeader.right - 2 * pad - 4 * S(4)) / 5);
        const int tabW = (std::min)((int)sz.cx + S(22), maxTabW);
        RECT tr = { tabX, m_rcHeader.top + S(64), tabX + tabW, m_rcHeader.bottom - S(6) };
        bool on = (m_tab == td.id);
        bool hot = (m_hotBtn == td.cmd);
        if (on)       p.FillRoundRect(tr, S(6), clr::SurfaceHi);
        else if (hot) p.FillRoundRect(tr, S(6), clr::Surface);
        p.Text(label, tr, m_fBold, on ? clr::Text : clr::TextDim, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
        if (on) {
            RECT ul = { tr.left + S(10), tr.bottom - S(2), tr.right - S(10), tr.bottom };
            p.FillRoundRect(ul, S(1), clr::Accent);
        }
        Button b;
        b.id = td.cmd;
        b.rc = tr;
        b.visible = false;
        m_buttons.push_back(b);
        tabX = tr.right + S(4);
    }

    const int headW = m_rcHeader.right - m_rcHeader.left;
    const bool wideHeader = headW >= S(1180);
    int gw = wideHeader ? S(190) : 0;
    RECT graph = { m_rcHeader.right - S(14) - gw, m_rcHeader.top + S(12),
                   m_rcHeader.right - S(14), m_rcHeader.top + S(50) };
    if (wideHeader) DrawSparkline(p, graph);
    else graph.left = m_rcHeader.right - S(6);

    wchar_t buf[160];
    swprintf(buf, 160, L"↓ %s", FormatBytesPerSec(m_mon.SystemRateIn()).c_str());
    RECT rIn = { graph.left - S(230), m_rcHeader.top + S(8), graph.left - S(116), m_rcHeader.top + S(28) };
    p.Text(buf, rIn, m_fBig, clr::Accent, DT_RIGHT | DT_VCENTER | DT_SINGLELINE);
    swprintf(buf, 160, L"↑ %s", FormatBytesPerSec(m_mon.SystemRateOut()).c_str());
    RECT rOut = { graph.left - S(230), m_rcHeader.top + S(26), graph.left - S(116), m_rcHeader.top + S(46) };
    p.Text(buf, rOut, m_fBig, clr::Purple, DT_RIGHT | DT_VCENTER | DT_SINGLELINE);
    RECT rSrc = { graph.left - S(230), m_rcHeader.top + S(44), graph.left - S(116), m_rcHeader.top + S(58) };
    p.Text(Tr(L"system-wide (NIC)"), rSrc, m_fSmall, clr::TextFaint, DT_RIGHT | DT_VCENTER | DT_SINGLELINE);

    int danger = 0, warn = 0;
    for (const auto& c : m_rows) {
        if (c.risk == Risk::Danger) danger++;
        else if (c.risk == Risk::Warn) warn++;
    }
    RECT rc1 = { graph.left - S(110), m_rcHeader.top + S(12), graph.left - S(14), m_rcHeader.top + S(31) };
    RECT rc2 = { graph.left - S(110), m_rcHeader.top + S(33), graph.left - S(14), m_rcHeader.top + S(52) };
    swprintf(buf, 160, Tr(L"%d critical"), danger);
    DrawBadge(p, rc1, buf, danger ? clr::Red : clr::TextDim, danger ? RGB(60, 24, 24) : clr::Surface);
    swprintf(buf, 160, Tr(L"%d suspicious"), warn);
    DrawBadge(p, rc2, buf, warn ? clr::Orange : clr::TextDim, warn ? RGB(58, 36, 18) : clr::Surface);

    p.Line(0, m_rcHeader.bottom - 1, m_rcHeader.right, m_rcHeader.bottom - 1, clr::Border);
}

void App::DrawButton(Painter& p, const Button& b) {
    if (!b.visible) return;
    COLORREF bg   = clr::Surface;
    COLORREF fg   = clr::Text;
    COLORREF edge = clr::Border;
    if (b.primary) { bg = clr::AccentDim; edge = clr::Accent; }
    if (b.toggle && b.active) { bg = clr::AccentDim; edge = clr::Accent; }
    if (b.danger && b.enabled) { bg = clr::Surface; edge = clr::Red; fg = clr::Red; }
    if (m_hotBtn == b.id) {
        if (b.danger) { bg = clr::Red; fg = RGB(255, 255, 255); }
        else          bg = (b.primary || (b.toggle && b.active)) ? clr::Accent : clr::SurfaceHi;
    }
    if (!b.enabled) { bg = clr::Surface; fg = clr::TextFaint; edge = clr::Border; }
    p.FillRoundRect(b.rc, S(6), bg);
    p.StrokeRoundRect(b.rc, S(6), edge);
    p.Text(b.label, b.rc, m_fBold, fg, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
}

void App::DrawToolbar(Painter& p) {
    p.FillRect(m_rcToolbar, clr::Bg);
    for (const auto& b : m_buttons) DrawButton(p, b);

    p.FillRoundRect(m_rcSearch, S(6), clr::Surface);
    p.StrokeRoundRect(m_rcSearch, S(6), (GetFocus() == m_search) ? clr::Accent : clr::Border);
    RECT ic = { m_rcSearch.left + S(8), m_rcSearch.top, m_rcSearch.left + S(26), m_rcSearch.bottom };
    p.Text(L"⌕", ic, m_fBig, clr::TextDim, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    if (m_searchText.empty() && GetFocus() != m_search) {
        RECT ph = { m_rcSearch.left + S(28), m_rcSearch.top, m_rcSearch.right - S(8), m_rcSearch.bottom };
        p.Text(Tr(L"search  •  proc:chrome  ip:142.250  port:443  country:US  risk:>50   (Ctrl+F)"),
               ph, m_fUi, clr::TextFaint, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
    }
    p.Line(0, m_rcToolbar.bottom - 1, m_rcToolbar.right, m_rcToolbar.bottom - 1, clr::Border);
}

void App::DrawTable(Painter& p) {
    const Column* cols = Cols();
    const int sortCol = const_cast<App*>(this)->SortCol();
    const int sortDir = const_cast<App*>(this)->SortDir();

    p.FillRect(m_rcTableHead, clr::Bg);
    for (size_t k = 0; k < m_visCols.size(); ++k) {
        const Column& col = cols[m_visCols[k]];
        RECT r = { m_colX[k], m_rcTableHead.top, m_colX[k] + m_colW[k] - S(8), m_rcTableHead.bottom };
        bool active = (col.id == sortCol);
        std::wstring title = Tr(col.title);
        if (active) title += (sortDir < 0 ? L"  ↓" : L"  ↑");
        p.Text(title, r, m_fSmallBold, active ? clr::Accent : ((int)k == m_hotCol ? clr::Text : clr::TextDim),
               col.align | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
    }
    p.Line(m_rcTableHead.left, m_rcTableHead.bottom - 1, m_rcTableHead.right,
           m_rcTableHead.bottom - 1, clr::Border);

    p.FillRect(m_rcRows, clr::Bg);
    const int rowH = RowH();
    const int first = (std::max)(0, m_scrollY / rowH);
    const int last  = (std::min)(TotalRows(), first + (int)((m_rcRows.bottom - m_rcRows.top) / rowH) + 2);

    HRGN clip = CreateRectRgn(m_rcRows.left, m_rcRows.top, m_rcRows.right, m_rcRows.bottom);
    SelectClipRgn(p.dc(), clip);

    if (TotalRows() == 0) {
        RECT r = m_rcRows;
        p.Text(m_paused ? Tr(L"Monitoring paused — press Space to resume")
                        : Tr(L"No rows match the filter"),
               r, m_fUi, clr::TextFaint, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    }

    const auto& hents = m_hist.Entries();

    for (int i = first; i < last; ++i) {
        int y = m_rcRows.top + i * rowH - m_scrollY;
        RECT rr = { m_rcRows.left, y, m_rcRows.right, y + rowH };
        if (rr.bottom < m_rcRows.top || rr.top > m_rcRows.bottom) continue;

        const bool sel   = (i == m_selRow);
        const bool hover = (i == m_hoverRow);
        COLORREF bg = (i % 2) ? clr::RowAlt : clr::Bg;
        if (hover) bg = clr::RowHover;
        if (sel)   bg = clr::RowSel;
        p.FillRect(rr, bg);

        Risk risk = Risk::Safe;
        int  score = 0;
        bool dim = false;
        (void)score;
        if (m_tab == Tab::Conns)        { risk = m_rows[m_view[i]].risk;  score = m_rows[m_view[i]].riskScore; }
        else if (m_tab == Tab::Apps)    { risk = m_apps[m_view[i]].risk;  score = m_apps[m_view[i]].riskScore; }
        else if (m_tab == Tab::History) { risk = hents[m_view[i]].risk;   score = hents[m_view[i]].riskScore;
                                          dim  = !hents[m_view[i]].active; }

        if ((int)risk >= (int)Risk::Warn) {
            if (risk == Risk::Danger && !sel) {
                RECT tint = rr;
                tint.left += S(3);
                p.FillRect(tint, RGB(38, 20, 22));
            }
            RECT stripe = { rr.left, rr.top + S(3), rr.left + S(3), rr.bottom - S(3) };
            p.FillRoundRect(stripe, S(2), RiskColor(risk));
        }

        for (size_t k = 0; k < m_visCols.size(); ++k) {
            const Column& col = cols[m_visCols[k]];
            RECT cr = { m_colX[k], rr.top, m_colX[k] + m_colW[k] - S(8), rr.bottom };
            std::wstring txt;
            COLORREF fg = clr::Text;
            HFONT f = col.mono ? m_fMono : m_fUi;

            if (m_tab == Tab::Conns) {
                const Conn& c = m_rows[m_view[i]];
                txt = CellText(c, col.id);
                switch (col.id) {
                    case C_PROC:
                        f = m_fBold;
                        if (c.procSuspended) { fg = clr::Yellow; txt = L"⏸ " + txt; }
                        break;
                    case C_PUB:   fg = (c.publisher == L"—") ? clr::TextFaint : clr::TextDim; break;
                    case C_SIGN:  fg = SignColor(c.sign); f = m_fSmallBold; break;
                    case C_PID:   fg = clr::TextDim; break;
                    case C_PROTO: fg = c.IsTcp() ? clr::Cyan : clr::Purple; break;
                    case C_STATE:
                        fg = (c.state == MIB_TCP_STATE_ESTAB) ? clr::Green
                           : (c.state == MIB_TCP_STATE_LISTEN) ? clr::Yellow : clr::TextDim;
                        break;
                    case C_PORTSVC: fg = (txt[0] == L'⚠') ? clr::Orange : clr::TextDim; break;
                    case C_DOWN: fg = c.rateIn  > 0.5 ? clr::Accent : clr::TextFaint; break;
                    case C_UP:   fg = c.rateOut > 0.5 ? clr::Purple : clr::TextFaint; break;
                    case C_TOTAL:
                    case C_AGE:
                    case C_RTT:  fg = clr::TextDim; break;
                    case C_GEO:
                    case C_CITY:
                    case C_ASN:
                    case C_ORG:
                    case C_HOST: fg = c.geoPending ? clr::TextFaint : clr::TextDim; break;
                    case C_MODULE: fg = clr::TextDim; break;
                    case C_THREAT: {
                        bool bad = !c.threatDnsbl.empty() && c.threatDnsbl != L"—";
                        fg = (bad || c.threatScore >= 50) ? clr::Red
                           : (c.threatScore >= 25) ? clr::Orange
                           : c.threatPending ? clr::TextFaint : clr::TextDim;
                        break;
                    }
                    case C_CERT:
                        fg = (c.certSelfSigned || c.certExpired || c.certMismatch) ? clr::Orange
                           : c.certPending ? clr::TextFaint : clr::TextDim;
                        break;
                    case C_REMOTE: fg = c.isRemotePublic ? clr::Text : clr::TextDim; break;
                    case C_RISK:
                        DrawRiskCell(p, cr, c.risk, c.riskScore, txt);
                        continue;
                }
            } else if (m_tab == Tab::Apps) {
                const AppRow& a = m_apps[m_view[i]];
                txt = AppCellText(a, col.id);
                switch (col.id) {
                    case A_PROC:
                        f = m_fBold;
                        if (a.suspended) { fg = clr::Yellow; txt = L"⏸ " + txt; }
                        else if (a.elevated) txt = L"⬆ " + txt;
                        break;
                    case A_SIGN: fg = SignColor(a.sign); f = m_fSmallBold; break;
                    case A_CPU:  fg = a.cpu > 25.0 ? clr::Orange : (a.cpu > 1.0 ? clr::Text : clr::TextFaint); break;
                    case A_RAM:  fg = a.ram > 1024ull*1024*1024 ? clr::Orange : clr::TextDim; break;
                    case A_IO:   fg = a.ioRate > 1024.0 ? clr::Cyan : clr::TextFaint; break;
                    case A_THREADS:
                    case A_UPTIME: fg = clr::TextDim; break;
                    case A_PID:
                    case A_USER:
                    case A_SVC:
                    case A_PUB:
                    case A_TOTAL:
                    case A_COUNTRIES:
                    case A_PATH: fg = clr::TextDim; break;
                    case A_DOWN: fg = a.rateIn  > 0.5 ? clr::Accent : clr::TextFaint; break;
                    case A_UP:   fg = a.rateOut > 0.5 ? clr::Purple : clr::TextFaint; break;
                    case A_REMOTE: fg = a.publicConns ? clr::Text : clr::TextFaint; break;
                    case A_RISK:
                        DrawRiskCell(p, cr, a.risk, a.riskScore, txt);
                        continue;
                }
            } else {
                const HistEntry& h = hents[m_view[i]];
                txt = HistCellText(h, col.id);
                switch (col.id) {
                    case H_PROC:  f = m_fBold; break;
                    case H_TIME:  fg = clr::TextDim; break;
                    case H_STATE: fg = h.active ? clr::Green : clr::TextFaint; break;
                    case H_IN:    fg = h.bytesIn  ? clr::Accent : clr::TextFaint; break;
                    case H_OUT:   fg = h.bytesOut ? clr::Purple : clr::TextFaint; break;
                    case H_GEO:
                    case H_ORG:
                    case H_HOST:
                    case H_SVC:
                    case H_DUR:   fg = clr::TextDim; break;
                    case H_MODULE: fg = clr::TextDim; break;
                    case H_THREAT: {
                        bool bad = !h.threatDnsbl.empty() && h.threatDnsbl != L"—";
                        fg = (bad || h.threatScore >= 50) ? clr::Red
                           : (h.threatScore >= 25) ? clr::Orange : clr::TextDim;
                        break;
                    }
                    case H_RISK:
                        DrawRiskCell(p, cr, h.risk, h.riskScore, txt);
                        continue;
                }
                if (dim && fg == clr::Text) fg = clr::TextDim;
            }
            p.Text(txt, cr, f, fg, col.align | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
        }
    }

    SelectClipRgn(p.dc(), nullptr);
    DeleteObject(clip);

    const int contentH = TotalRows() * rowH;
    const int viewH    = m_rcRows.bottom - m_rcRows.top;
    if (contentH > viewH && viewH > 0) {
        RECT track = m_rcScroll;
        p.FillRoundRect(track, S(4), clr::RowAlt);
        int thumbH = (std::max)(S(30), MulDiv(viewH, viewH, contentH));
        int maxScroll = contentH - viewH;
        int ty = track.top + (maxScroll > 0 ? MulDiv(m_scrollY, viewH - thumbH, maxScroll) : 0);
        RECT thumb = { track.left + S(2), ty, track.right - S(2), ty + thumbH };
        p.FillRoundRect(thumb, S(3), m_dragScroll ? clr::Accent : clr::Border);
    }
}

void App::DrawBarList(Painter& p, RECT area, const std::wstring& title,
                      const std::vector<CountItem>& items, COLORREF accent, bool bytes) {
    p.FillRoundRect(area, S(8), clr::Surface);
    p.StrokeRoundRect(area, S(8), clr::Border);

    RECT tr = { area.left + S(14), area.top + S(8), area.right - S(12), area.top + S(30) };
    p.Text(title, tr, m_fBold, clr::Text, DT_LEFT | DT_VCENTER | DT_SINGLELINE);

    if (items.empty()) {
        RECT er = area;
        er.top += S(30);
        p.Text(Tr(L"no data"), er, m_fSmall, clr::TextFaint, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        return;
    }

    double maxV = 0;
    for (const auto& it : items) maxV = (std::max)(maxV, it.value);
    if (maxV <= 0) maxV = 1;

    int y = area.top + S(34);
    const int rowH = S(24);
    const int labelW = S(150);
    for (const auto& it : items) {
        if (y + rowH > area.bottom - S(4)) break;
        RECT lr = { area.left + S(14), y, area.left + S(14) + labelW, y + rowH };
        p.Text(it.label, lr, m_fUi, clr::Text, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);

        int barLeft  = lr.right + S(8);
        int barRight = area.right - S(96);
        int w = (int)((barRight - barLeft) * (it.value / maxV));
        if (w < S(3)) w = S(3);
        RECT track = { barLeft, y + S(6), barRight, y + rowH - S(6) };
        p.FillRoundRect(track, S(3), clr::RowAlt);
        RECT bar = { barLeft, y + S(6), barLeft + w, y + rowH - S(6) };
        p.FillRoundRect(bar, S(3), accent);

        std::wstring val = bytes ? FormatBytesPerSec(it.value)
                                 : (std::to_wstring(it.count) + L"×");
        RECT vr = { barRight + S(6), y, area.right - S(12), y + rowH };
        p.Text(val, vr, m_fSmall, clr::TextDim, DT_RIGHT | DT_VCENTER | DT_SINGLELINE);

        if (!it.sub.empty()) {
            RECT sr = { lr.left, y + rowH / 2, lr.right, y + rowH };
            (void)sr;
        }
        y += rowH;
    }
}

static std::wstring ClockText(unsigned long long ts, DWORD flags) {
    time_t tt = (time_t)ts;
    tm lt;
    localtime_s(&lt, &tt);
    SYSTEMTIME st = {};
    st.wYear = (WORD)(lt.tm_year + 1900); st.wMonth = (WORD)(lt.tm_mon + 1);
    st.wDay = (WORD)lt.tm_mday;  st.wHour = (WORD)lt.tm_hour;
    st.wMinute = (WORD)lt.tm_min; st.wSecond = (WORD)lt.tm_sec;
    wchar_t tb[64];
    if (!GetTimeFormatW(LOCALE_USER_DEFAULT, flags, &st, nullptr, tb, 64)) tb[0] = 0;
    return tb;
}

std::wstring FetchAgeText(unsigned long long ts) {
    if (!ts) return std::wstring();
    std::wstring tb = ClockText(ts, TIME_NOSECONDS);
    unsigned long long age = (unsigned long long)time(nullptr) - ts;
    wchar_t rel[64];
    if (age < 60)        wcscpy_s(rel, Tr(L"just now"));
    else if (age < 3600) swprintf(rel, 64, Tr(L"%d min ago"), (int)(age / 60));
    else if (age < 86400) swprintf(rel, 64, Tr(L"%d h ago"), (int)(age / 3600));
    else                 swprintf(rel, 64, Tr(L"%d days ago"), (int)(age / 86400));
    wchar_t out[128];
    swprintf(out, 128, Tr(L"fetched: %s (%s)"), tb.c_str(), rel);
    return out;
}

void App::DrawStats(Painter& p) {
    RECT area = { m_rcTable.left, m_rcTableHead.top, m_rcTable.right, m_rcTable.bottom };
    p.FillRect(area, clr::Bg);

    const int pad = S(12);
    const int W = area.right - area.left - pad * 2;

    int top = area.top + pad;
    if (m_demo) {
        const int bh = S(54);
        RECT br = { area.left + pad, top, area.right - pad, top + bh };
        p.FillRoundRect(br, S(8), clr::Surface);
        p.StrokeRoundRect(br, S(8), clr::Cyan);
        int danger = 0, warn = 0;
        std::unordered_set<std::wstring> countries, procs;
        for (const auto& c : m_rows) {
            if (c.risk == Risk::Danger) danger++;
            else if (c.risk == Risk::Warn) warn++;
            if (!c.countryCode.empty()) countries.insert(c.countryCode);
            procs.insert(c.procName);
        }
        wchar_t db[300];
        swprintf(db, 300, Tr(L"DEMO ENVIRONMENT — %d connections • %d processes • %d suspicious • %d high-risk • %d countries"),
                 (int)m_rows.size(), (int)procs.size(), warn, danger, (int)countries.size());
        RECT tr = { br.left + S(14), br.top, br.right - S(150), br.bottom };
        p.Text(db, tr, m_fBold, clr::Cyan, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
        RECT er = { br.right - S(128), br.top + S(13), br.right - S(12), br.bottom - S(13) };
        p.FillRoundRect(er, S(6), m_hotBtn == ID_BTN_DEMO_EXIT ? clr::Cyan : clr::SurfaceHi);
        p.Text(Tr(L"EXIT DEMO"), er, m_fBold,
               m_hotBtn == ID_BTN_DEMO_EXIT ? clr::Bg : clr::Cyan,
               DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        m_rcDemoExit = er;
        top += bh + S(10);
    }

    int danger = 0, warn = 0, pub = 0, listen = 0, tcp = 0, udp = 0, unsigned_ = 0;
    int certWarn = 0;
    std::unordered_set<std::wstring> blacklisted;
    for (const auto& c : m_rows) {
        if (c.risk == Risk::Danger) danger++;
        else if (c.risk == Risk::Warn) warn++;
        if (c.isRemotePublic) pub++;
        if (c.IsListening()) listen++;
        if (c.IsTcp()) tcp++; else udp++;
        if (c.sign == SignState::Unsigned || c.sign == SignState::Invalid) unsigned_++;
        if (!c.threatDnsbl.empty() && c.threatDnsbl != L"—") blacklisted.insert(c.remoteIp);
        if (c.certSelfSigned || c.certExpired || c.certMismatch) certWarn++;
    }

    struct Kpi { std::wstring value; std::wstring label; COLORREF color; bool compact = false; };
    const Kpi kpis[] = {
        { std::to_wstring((int)m_rows.size()),  Tr(L"open sockets"),             clr::Text },
        { std::to_wstring(pub),                 Tr(L"internet connections"),    clr::Accent },
        { std::to_wstring((int)m_apps.size()),  Tr(L"apps using network"),   clr::Cyan },
        { std::to_wstring(listen),              Tr(L"listening ports"),          clr::Yellow },
        { std::to_wstring(warn),                Tr(L"suspicious"),                clr::Orange },
        { std::to_wstring(danger),              Tr(L"critical"),                 clr::Red },
        { std::to_wstring((int)blacklisted.size()), Tr(L"blacklisted IPs"),    clr::Red },
        { std::to_wstring(certWarn),            Tr(L"cert warnings"),      clr::Orange },
        { std::to_wstring(tcp) + L"/" + std::to_wstring(udp), Tr(L"tcp / udp"),  clr::Purple },
        { std::to_wstring(unsigned_),           Tr(L"unsigned process sockets"),   clr::Orange },
        { FormatBytesPerSec(m_mon.SystemRateIn()),  Tr(L"system download"),     clr::Accent },
        { FormatBytesPerSec(m_mon.SystemRateOut()), Tr(L"system upload"),     clr::Purple },
        { std::to_wstring((int)m_dns.CacheSize()),  Tr(L"DNS cache entries"), clr::Cyan, true },
        { std::to_wstring(m_dns.HostsEntryCount()), Tr(L"hosts redirects"),
          m_dns.HostsEntryCount() ? clr::Red : clr::TextDim, true },
        { std::to_wstring((int)m_mon.LanDevicesActive()), Tr(L"LAN devices active"), clr::Green, true },
        { std::to_wstring(m_mon.SynRcvdCount()),  Tr(L"scanned port hits"),
          m_mon.SynRcvdCount() ? clr::Red : clr::TextDim, true },
    };
    const int kpiH = S(72);
    const int kpiCount = (int)(sizeof(kpis) / sizeof(kpis[0]));
    const int kpiW = (W - S(10) * (kpiCount - 1)) / kpiCount;
    int x = area.left + pad;
    for (const auto& k : kpis) {
        RECT r = { x, top, x + kpiW, top + kpiH };
        p.FillRoundRect(r, S(8), clr::Surface);
        p.StrokeRoundRect(r, S(8), clr::Border);
        RECT vr = { r.left + S(12), r.top + S(8), r.right - S(8), r.top + S(44) };
        p.Text(k.value, vr, k.compact ? m_fTitle : m_fHuge, k.color,
               DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
        RECT lr = { r.left + S(13), r.top + S(44), r.right - S(8), r.bottom - S(6) };
        p.Text(k.label, lr, m_fSmall, clr::TextDim, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
        x += kpiW + S(10);
    }

    int gy = top + kpiH + S(10);
    int graphH = (std::max)(S(120), (int)((area.bottom - gy) / 3));
    RECT graph = { area.left + pad, gy, area.right - pad, gy + graphH };
    p.FillRoundRect(graph, S(8), clr::Surface);
    p.StrokeRoundRect(graph, S(8), clr::Border);
    RECT gTitle = { graph.left + S(14), graph.top + S(6), graph.right - S(14), graph.top + S(26) };
    wchar_t hbuf[256];
    swprintf(hbuf, 256,
             Tr(L"System traffic (NIC)   ↓ %s   ↑ %s   •   session: ↓ %s / ↑ %s   •   monitored sockets: ↓ %s / ↑ %s"),
             FormatBytesPerSec(m_mon.SystemRateIn()).c_str(),
             FormatBytesPerSec(m_mon.SystemRateOut()).c_str(),
             FormatBytes(m_mon.SystemBytesIn()).c_str(),
             FormatBytes(m_mon.SystemBytesOut()).c_str(),
             FormatBytesPerSec(m_mon.TotalRateIn()).c_str(),
             FormatBytesPerSec(m_mon.TotalRateOut()).c_str());
    p.Text(hbuf, gTitle, m_fBold, clr::Text, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
    RECT inner = { graph.left + S(10), graph.top + S(28), graph.right - S(10), graph.bottom - S(8) };
    DrawSparkline(p, inner);

    int by = graph.bottom + S(10);
    if (by + S(90) < area.bottom) {
        const int colW4 = (W - pad * 3) / 4;
        RECT b1 = { area.left + pad,        by, area.left + pad + colW4, area.bottom - pad };
        RECT b2 = { b1.right + pad,         by, b1.right + pad + colW4,  area.bottom - pad };
        RECT b3 = { b2.right + pad,         by, b2.right + pad + colW4,  area.bottom - pad };
        RECT b4 = { b3.right + pad,         by, area.right - pad,        area.bottom - pad };
        DrawBarList(p, b1, Tr(L"Top traffic apps"), m_hist.TopApps(m_rows, 8), clr::Accent, true);
        DrawBarList(p, b2, Tr(L"Destination countries"),                    m_hist.TopCountries(m_rows, 8), clr::Cyan, false);
        DrawBarList(p, b3, Tr(L"Destination ports / services"),        m_hist.TopPorts(m_rows, 8), clr::Purple, false);

        p.FillRoundRect(b4, S(8), clr::Surface);
        p.StrokeRoundRect(b4, S(8), clr::Border);
        RECT t4 = { b4.left + S(12), b4.top + S(6), b4.right - S(12), b4.top + S(26) };
        p.Text(Tr(L"Network environment"), t4, m_fBold, clr::Text, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
        int ay = b4.top + S(30);
        const int lh = S(30);

        if (m_wifiLoaded && m_wifi.ok) {
            wchar_t wb[220];
            swprintf(wb, 220, Tr(L"Wi-Fi: %s  •  signal %d%%  •  %s"),
                     m_wifi.ssid.empty() ? L"?" : m_wifi.ssid.c_str(),
                     m_wifi.signal, m_wifi.security.empty() ? Tr(L"security unknown") : m_wifi.security.c_str());
            RECT wr = { b4.left + S(12), ay, b4.right - S(12), ay + S(16) };
            p.Text(wb, wr, m_fSmallBold, m_wifi.signal > 40 ? clr::Green : clr::Orange,
                   DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
            wchar_t wb2[220];
            swprintf(wb2, 220, L"BSSID %s  •  ↓%lu Mbps  ↑%lu Mbps  •  %s",
                     m_wifi.bssid.empty() ? L"-" : m_wifi.bssid.c_str(),
                     m_wifi.rxRate / 1000000, m_wifi.txRate / 1000000,
                     m_wifi.state.empty() ? L"" : m_wifi.state.c_str());
            RECT wr2 = { b4.left + S(12), ay + S(15), b4.right - S(12), ay + S(29) };
            p.Text(wb2, wr2, m_fSmall, clr::TextDim, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
            ay += lh;
        }

        for (const auto& ev : m_mon.PortScanEvents()) {
            if (ay + lh > b4.bottom - S(6)) break;
            wchar_t sb[220];
            swprintf(sb, 220, Tr(L"⚠ port %u is being scanned: %u distinct IPs (%s)"), ev.port, ev.count,
                     ev.sample.c_str());
            RECT sr = { b4.left + S(12), ay, b4.right - S(12), ay + S(16) };
            p.Text(sb, sr, m_fSmallBold, clr::Red, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
            ay += S(18);
        }

        for (const auto& ad : m_mon.Adapters()) {
            if (ay + lh > b4.bottom - S(6)) break;
            RECT nr = { b4.left + S(12), ay, b4.right - S(12), ay + S(16) };
            p.Text((ad.up ? L"● " : L"○ ") + ad.name, nr, m_fSmallBold,
                   ad.up ? clr::Green : clr::TextFaint, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
            wchar_t ab[300];
            swprintf(ab, 300, L"↓ %s  ↑ %s%s%s%s%s",
                     FormatBytes(ad.inBytes).c_str(), FormatBytes(ad.outBytes).c_str(),
                     ad.speed ? L"  •  " : L"",
                     ad.speed ? (ad.speed >= 1000000000ull ? Tr(L"1+ Gbps") : Tr(L"100 Mbps class")) : L"",
                     ad.gateway.empty() ? L"" : Tr(L"  •  gw "),
                     ad.gateway.empty() ? L"" : ad.gateway.c_str());
            RECT dr = { b4.left + S(12), ay + S(15), b4.right - S(12), ay + S(29) };
            p.Text(ab, dr, m_fSmall, clr::TextDim, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
            ay += lh;
        }

        for (const auto& kv : m_anomAlerts) {
            if (ay + S(18) > b4.bottom - S(6)) break;
            const AnomAlert& al = kv.second;
            wchar_t ab2[220];
            swprintf(ab2, 220, Tr(L"⚠ anomaly: %s +%d%% connections (baseline: %d/min → %d/min)"),
                     al.name.c_str(), (std::max)(0, al.pct),
                     (int)al.baseline, (int)al.current);
            RECT ar2 = { b4.left + S(12), ay, b4.right - S(12), ay + S(16) };
            p.Text(ab2, ar2, m_fSmallBold, clr::Red,
                   DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
            ay += S(18);
        }

        const auto lan = m_mon.LanDevices();
        if (!lan.empty()) {
            int lanActive = 0;
            for (const auto& d : lan) if (d.active) lanActive++;
            wchar_t lbuf[160];
            swprintf(lbuf, 160, Tr(L"Local network: %d ARP entries • %d active now"),
                     (int)lan.size(), lanActive);
            std::wstring ls = lbuf;
            for (size_t i = 0, shown = 0; i < lan.size() && shown < 4; ++i) {
                if (!lan[i].active) continue;
                ls += L"  " + lan[i].ip;
                if (!lan[i].vendor.empty()) ls += L" (" + lan[i].vendor + L")";
                shown++;
            }
            if (ay + S(18) <= b4.bottom - S(6)) {
                RECT lr = { b4.left + S(12), ay, b4.right - S(12), ay + S(16) };
                p.Text(ls, lr, m_fSmall, clr::TextDim, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
                ay += S(18);
            }
        }
        if (m_fwChecked && !m_blockedIps.empty() && ay + S(18) <= b4.bottom - S(6)) {
            wchar_t fb[160];
            swprintf(fb, 160, Tr(L"Firewall: %d NetLurker block rules active"), (int)m_blockedIps.size());
            RECT fr = { b4.left + S(12), ay, b4.right - S(12), ay + S(16) };
            p.Text(fb, fr, m_fSmall, clr::Green, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
            ay += S(18);
        }
        if (m_mon.Adapters().empty()) {
            RECT er = { b4.left + S(12), ay, b4.right - S(12), ay + S(20) };
            p.Text(Tr(L"interface info unavailable"), er, m_fSmall, clr::TextFaint,
                   DT_LEFT | DT_VCENTER | DT_SINGLELINE);
        }
    }
}

void App::DrawDetail(Painter& p) {
    if (!m_showDetail || !IsTableTab()) return;
    p.FillRect(m_rcDetail, clr::Bg);
    p.Line(m_rcDetail.left, m_rcDetail.top, m_rcDetail.right, m_rcDetail.top, clr::Border);

    RECT card = { m_rcDetail.left + S(12), m_rcDetail.top + S(8),
                  m_rcDetail.right - S(12), m_rcDetail.bottom - S(8) };
    p.FillRoundRect(card, S(8), clr::Surface);
    p.StrokeRoundRect(card, S(8), clr::Border);

    const Conn*      c = SelectedConn();
    const AppRow*    a = SelectedApp();
    const HistEntry* h = SelectedHist();

    if (!c && !a && !h) {
        p.Text(Tr(L"Select a row for details  •  double-click starts AI analysis"),
               card, m_fUi, clr::TextFaint, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        return;
    }

    const int splitX = card.left + (card.right - card.left) * 46 / 100;
    int x = card.left + S(14);
    int y = card.top + S(8);
    const int lineH = S(18);

    auto row = [&](const wchar_t* label, const std::wstring& value, COLORREF vc = clr::Text, bool mono = false) {
        if (y + lineH > card.bottom - S(4)) return;
        RECT lr = { x, y, x + S(92), y + lineH };
        p.Text(label, lr, m_fSmall, clr::TextFaint, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
        RECT vr = { x + S(96), y, splitX - S(10), y + lineH };
        p.Text(value.empty() ? L"—" : value, vr, mono ? m_fMono : m_fUi, vc,
               DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
        y += lineH;
    };

    std::wstring graphProc;

    if (c) {
        ProcDetails d = m_mon.Procs().Get(c->pid);
        std::wstring title = c->procName + L"  (PID " + std::to_wstring(c->pid) + L")";
        RECT tr = { x, y, splitX - S(120), y + S(22) };
        p.Text(title, tr, m_fBig, clr::Text, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
        RECT sb = { splitX - S(118), y + S(2), splitX - S(56), y + S(20) };
        DrawBadge(p, sb, c->RiskText(), RiskColor(c->risk), RiskBg(c->risk));
        RECT scr = { splitX - S(52), y, splitX - S(10), y + S(22) };
        p.Text(std::to_wstring(c->riskScore) + L"/100", scr, m_fSmallBold, RiskColor(c->risk),
               DT_RIGHT | DT_VCENTER | DT_SINGLELINE);
        y += S(24);
        graphProc = c->procName;

        row(Tr(L"Publisher"),  c->publisher + L"   [" + CellText(*c, C_SIGN) + L"]",
            SignColor(c->sign));
        if (!d.product.empty() || !d.description.empty())
            row(Tr(L"Product"), (d.description.empty() ? d.product : d.description) +
                         (d.fileVersion.empty() ? L"" : (L"   v" + d.fileVersion)), clr::TextDim);
        row(Tr(L"Path"),      c->procPath);
        if (!d.cmdline.empty()) row(Tr(L"Command"), d.cmdline, clr::TextDim);
        row(Tr(L"User"),d.user + (d.services.empty() ? L"" : (Tr(L"   •   service: ") + d.services)), clr::TextDim);
        {
            ProcRuntime rt = m_mon.Procs().Runtime(c->pid);
            wchar_t rb[320];
            swprintf(rb, 320, Tr(L"CPU %.1f%%   •   RAM %s   •   %lu threads / %lu handles   •   disk %s"),
                     rt.cpu, FormatBytes(rt.workingSet).c_str(), rt.threads, rt.handles,
                     FormatBytesPerSec(rt.ioReadRate + rt.ioWriteRate).c_str());
            row(Tr(L"Source"), rb, rt.suspended ? clr::Yellow : clr::TextDim);
            std::wstring sec = std::wstring(IntegrityText(d.integrity));
            if (d.elevated)  sec += Tr(L"   •   elevated");
            if (!d.is64)     sec += Tr(L"   •   32-bit");
            if (rt.suspended)sec += Tr(L"   •   SUSPENDED");
            if (d.parentPid) sec += Tr(L"   •   parent: ") +
                                    (d.parentName.empty() ? std::wstring(L"PID ") : (d.parentName + L" #")) +
                                    std::to_wstring(d.parentPid);
            row(Tr(L"Process"), sec, rt.suspended ? clr::Yellow : clr::TextDim);
            std::wstring fileLine = d.startTime ? (Tr(L"started ") + d.AgeText() + Tr(L" ago")) : std::wstring(L"—");
            if (d.fileSize) fileLine += Tr(L"   •   file ") + FormatBytes(d.fileSize);
            if (!d.sha256.empty()) fileLine += L"   •   sha256 " + d.sha256.substr(0, d.sha256.size() < 24 ? d.sha256.size() : 24) + L"…";
            row(Tr(L"File"), fileLine, clr::TextFaint);
        }
        row(Tr(L"Connection"), c->LocalText() + L"  →  " + c->RemoteText(), clr::Text, true);
        {
            std::wstring proto = c->ProtoText() + L" / " + c->StateText();
            const wchar_t* svc = PortServiceName(c->IsListening() ? c->localPort : c->remotePort);
            if (svc) proto += L"   •   " + std::wstring(svc);
            const wchar_t* thr = PortThreatNote(c->IsListening() ? c->localPort : c->remotePort);
            row(Tr(L"Protocol"), proto, thr ? clr::Orange : clr::Text);
        }
        {
            GeoInfo g;
            std::wstring geo = c->country;
            if (!c->countryCode.empty()) geo = c->countryCode + L" · " + c->country;
            if (!c->city.empty())   geo += L", " + c->city;
            if (!c->region.empty() && c->region != c->city) geo += L" / " + c->region;
            row(Tr(L"Location"), geo, clr::TextDim);
            std::wstring net = c->org;
            if (!c->asn.empty())    net += L"   " + c->asn;
            if (c->isHosting) net += Tr(L"   [data center]");
            if (c->isProxy)   net += Tr(L"   [proxy/VPN]");
            if (c->isMobile)  net += Tr(L"   [mobile]");
            row(Tr(L"Network owner"), net, c->isProxy ? clr::Orange : clr::TextDim);
            if (c->geoTs) row(Tr(L"Data age"), FetchAgeText(c->geoTs), clr::TextFaint);
            (void)g;
        }
        row(Tr(L"rDNS"),     c->host, clr::TextDim);
        if (!c->domain.empty())
            row(Tr(L"Domain"), c->domain + (c->hostsRedirect ? Tr(L"  [hosts redirect]") : L""),
                c->hostsRedirect ? clr::Orange : clr::TextDim);
        if (!c->banner.empty() || c->bannerPending)
            row(Tr(L"Banner"), c->bannerPending ? Tr(L"querying…") :
                (c->banner + (c->bannerStatus.empty() ? L"" : (L"   [" + c->bannerStatus + L"]")) +
                 (c->bannerTs ? (L" • " + FetchAgeText(c->bannerTs)) : L"")),
                clr::TextDim);
        if (c->fwBlocked)
            row(Tr(L"Firewall"), Tr(L"blocked by a NetLurker rule (outbound)"), clr::Green);
        if (!c->module.empty())
            row(Tr(L"Module"), c->module, clr::Cyan);
        {

            std::wstring rdap;
            if (!c->rdapOrg.empty())  rdap += c->rdapOrg;
            if (!c->rdapCidr.empty()) rdap += (rdap.empty() ? L"" : L"  ") + (L"[" + c->rdapCidr + L"]");
            if (c->rdapRegistered) {
                time_t tt = (time_t)c->rdapRegistered;
                tm lt;
                localtime_s(&lt, &tt);
                wchar_t tb[32];
                swprintf(tb, 32, Tr(L"allocated since %02d.%02d.%d"),
                         lt.tm_mday, lt.tm_mon + 1, lt.tm_year + 1900);
                rdap += (rdap.empty() ? L"" : L" • ") + std::wstring(tb);
            }
            if (!rdap.empty()) row(Tr(L"RDAP"), rdap, clr::TextDim);
            if (!c->rdapAbuse.empty())
                row(Tr(L"Contact"), c->rdapAbuse, clr::TextFaint);

            if (c->vtTotal > 0) {
                std::wstring vt = std::to_wstring(c->vtMalicious) + L"/" + std::to_wstring(c->vtTotal) +
                                  Tr(L" engines flagged malicious");
                if (c->vtSuspicious) vt += L" • " + std::to_wstring(c->vtSuspicious) + Tr(L" suspicious");
                if (c->vtReputation) vt += Tr(L" • community score ") + std::to_wstring(c->vtReputation);
                row(Tr(L"VirusTotal"), vt, c->vtMalicious > 0 ? clr::Red : clr::TextDim);
            }
        }
        {

            std::wstring thr;
            if (c->threatScore >= 0) {
                thr = std::to_wstring(c->threatScore) + L"/100";
                if (c->threatReports > 0)
                    thr += L" • " + std::to_wstring(c->threatReports) + Tr(L" reports");
                if (c->threatLastReport) {
                    time_t tt = (time_t)c->threatLastReport;
                    tm lt;
                    localtime_s(&lt, &tt);
                    wchar_t tb[32];
                    swprintf(tb, 32, L"%02d.%02d.%d", lt.tm_mday, lt.tm_mon + 1, lt.tm_year + 1900);
                    thr += Tr(L" • last report ") + std::wstring(tb);
                }
                if (c->threatTor) thr += Tr(L" • Tor");
            } else if (c->threatPending) {
                thr = Tr(L"querying…");
            }
            if (!c->threatDnsbl.empty() && c->threatDnsbl != L"—")
                thr += (thr.empty() ? L"" : L" • ") + (Tr(L"blacklist: ") + c->threatDnsbl);
            if (c->threatDnsblIncomplete)
                row(L"DNSBL", Tr(L"(lookup failed)"), clr::TextDim);
            if (c->threatPdns > 0)
                thr += (thr.empty() ? L"" : L" • ") +
                       (Tr(L"passive DNS: ") + std::to_wstring(c->threatPdns) + Tr(L" records"));
            if (!c->threatPdnsNames.empty())
                row(Tr(L"Passive DNS"), c->threatPdnsNames, clr::TextDim);
            if (!thr.empty()) {
                if (c->threatTs) thr += L" • " + FetchAgeText(c->threatTs);
                bool bad = (!c->threatDnsbl.empty() && c->threatDnsbl != L"—") || c->threatScore >= 50;
                row(Tr(L"Threat"), thr, bad ? clr::Red : (c->threatScore >= 25 ? clr::Orange : clr::TextDim));
            }
        }
        if (!c->certIssuer.empty() || !c->certSubject.empty() || c->certPending) {
            std::wstring cert = c->certIssuer;
            if (!c->certSubject.empty()) cert += (cert.empty() ? L"" : L" • ") + (L"CN=" + c->certSubject);
            if (!c->certVersion.empty()) cert += (cert.empty() ? L"" : L" • ") + c->certVersion;
            if (c->certSelfSigned) cert += Tr(L" • SELF-SIGNED");
            if (c->certExpired)    cert += Tr(L" • EXPIRED");
            if (c->certNotYetValid) cert += Tr(L" • NOT YET VALID");
            if (c->certMismatch)   cert += Tr(L" • rDNS mismatch");
            if (c->certPending && cert.empty()) cert = Tr(L"querying…");
            bool certBad = c->certSelfSigned || c->certExpired || c->certMismatch;
            if (c->certTs && !cert.empty()) cert += L" • " + FetchAgeText(c->certTs);
            row(Tr(L"Certificate"), cert, certBad ? clr::Orange : clr::TextDim);
            if (!c->certSans.empty() && c->certSans != c->certSubject)
                row(Tr(L"SAN"), c->certSans, clr::TextFaint);
            if (!c->certThumbprint.empty())
                row(Tr(L"Fingerprint"), c->certThumbprint, clr::TextFaint, true);
            if (c->certNotAfter) {
                time_t tt = (time_t)c->certNotAfter;
                tm lt;
                localtime_s(&lt, &tt);
                wchar_t tb[32];
                swprintf(tb, 32, Tr(L"valid until %02d.%02d.%d"),
                         lt.tm_mday, lt.tm_mon + 1, lt.tm_year + 1900);
                row(Tr(L"Validity"), tb, c->certExpired ? clr::Red : clr::TextFaint);
            }
        }
        {

            wchar_t buf[320];
            const bool estats = c->bytesIn || c->bytesOut || c->rttMs;
            if (estats) {
                swprintf(buf, 320, Tr(L"↓ %s   ↑ %s   •   total ↓ %s / ↑ %s   •   RTT %u ms   •   age %s"),
                         FormatBytesPerSec(c->rateIn).c_str(), FormatBytesPerSec(c->rateOut).c_str(),
                         FormatBytes(c->bytesIn).c_str(), FormatBytes(c->bytesOut).c_str(),
                         c->rttMs, c->AgeText().c_str());
            } else {
                swprintf(buf, 320, Tr(L"↓ %s   ↑ %s   •   total/RTT: not measurable (%s)   •   age %s"),
                         FormatBytesPerSec(c->rateIn).c_str(), FormatBytesPerSec(c->rateOut).c_str(),
                         IsRunAsAdmin() ? Tr(L"no ESTATS for this socket")
                                        : Tr(L"requires administrator rights"),
                         c->AgeText().c_str());
            }
            row(Tr(L"Traffic"), buf, clr::TextDim);
        }
        row(Tr(L"Risk note"), c->riskReason, RiskColor(c->risk));
    } else if (a) {
        std::wstring title = a->name + L"  (PID " + std::to_wstring(a->pid) + L")";
        RECT tr = { x, y, splitX - S(120), y + S(22) };
        p.Text(title, tr, m_fBig, clr::Text, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
        RECT sb = { splitX - S(118), y + S(2), splitX - S(56), y + S(20) };
        DrawBadge(p, sb, AppCellText(*a, A_RISK), RiskColor(a->risk), RiskBg(a->risk));
        RECT scr = { splitX - S(52), y, splitX - S(10), y + S(22) };
        p.Text(std::to_wstring(a->riskScore) + L"/100", scr, m_fSmallBold, RiskColor(a->risk),
               DT_RIGHT | DT_VCENTER | DT_SINGLELINE);
        y += S(24);
        graphProc = a->name;

        row(Tr(L"Publisher"),  a->publisher + L"   [" + a->SignText() + L"]", SignColor(a->sign));
        row(Tr(L"Product"),     a->product + (a->version.empty() ? L"" : (L"  v" + a->version)), clr::TextDim);
        row(Tr(L"Path"),      a->path);
        if (!a->cmdline.empty()) row(Tr(L"Command"), a->cmdline, clr::TextDim);
        row(Tr(L"User"),a->user, clr::TextDim);
        if (!a->services.empty()) row(Tr(L"Services"), a->services, clr::Cyan);
        row(Tr(L"Connection"), std::to_wstring(a->conns) + Tr(L" open  •  ") + std::to_wstring(a->publicConns) +
                         Tr(L" internet  •  ") + std::to_wstring(a->listenPorts) + Tr(L" listening"));
        if (!a->domain.empty())
            row(Tr(L"Domain"), a->domain, clr::TextDim);
        row(Tr(L"Traffic"),   L"↓ " + FormatBytesPerSec(a->rateIn) + L"   ↑ " + FormatBytesPerSec(a->rateOut) +
                         Tr(L"   •   total ") + FormatBytes(a->bytesIn + a->bytesOut), clr::TextDim);
        {
            wchar_t rb[320];
            swprintf(rb, 320, Tr(L"CPU %.1f%%   •   RAM %s   •   %lu threads / %lu handles   •   disk %s   •   uptime %s"),
                     a->cpu, FormatBytes(a->ram).c_str(), a->threads, a->handles,
                     FormatBytesPerSec(a->ioRate).c_str(), a->UptimeText().c_str());
            row(Tr(L"Source"), rb, a->suspended ? clr::Yellow : clr::TextDim);
            std::wstring sec = std::wstring(IntegrityText(a->integrity));
            if (a->elevated)  sec += Tr(L"   •   elevated");
            if (a->suspended) sec += Tr(L"   •   SUSPENDED");
            row(Tr(L"Process"), sec, a->suspended ? clr::Yellow : clr::TextDim);
        }
        row(Tr(L"Countries"),  a->countries, clr::TextDim);
        row(Tr(L"Risk note"),a->riskReason, RiskColor(a->risk));
    } else if (h) {
        std::wstring title = h->proc + L"  →  " + h->remoteIp;
        RECT tr = { x, y, splitX - S(120), y + S(22) };
        p.Text(title, tr, m_fBig, clr::Text, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
        RECT sb = { splitX - S(118), y + S(2), splitX - S(56), y + S(20) };
        DrawBadge(p, sb, HistCellText(*h, H_RISK), RiskColor(h->risk), RiskBg(h->risk));
        y += S(24);
        graphProc = h->proc;

        row(Tr(L"Status"),    h->active ? Tr(L"still open") : Tr(L"closed"), h->active ? clr::Green : clr::TextDim);
        row(Tr(L"Destination"),    h->remoteIp + L":" + std::to_wstring(h->remotePort), clr::Text, true);
        row(Tr(L"Local"),    h->localAddr, clr::TextDim, true);
        row(Tr(L"Location"),    h->countryCode + L" " + h->country, clr::TextDim);
        row(Tr(L"Network owner"),h->org, clr::TextDim);
        row(Tr(L"rDNS"),     h->host, clr::TextDim);
        if (!h->domain.empty()) row(Tr(L"Domain"), h->domain, clr::TextDim);
        if (!h->banner.empty()) row(Tr(L"Banner"), h->banner, clr::TextFaint);
        if (!h->module.empty()) row(Tr(L"Module"), h->module, clr::Cyan);
        {
            std::wstring thr;
            if (h->threatScore >= 0) thr = std::to_wstring(h->threatScore) + L"/100";
            if (!h->threatDnsbl.empty() && h->threatDnsbl != L"—")
                thr += (thr.empty() ? L"" : L" • ") + (Tr(L"blacklist: ") + h->threatDnsbl);
            if (h->threatPdns > 0)
                thr += (thr.empty() ? L"" : L" • ") + (Tr(L"passive DNS: ") + std::to_wstring(h->threatPdns));
            if (!thr.empty()) {
                bool bad = h->threatScore >= 50 || (!h->threatDnsbl.empty() && h->threatDnsbl != L"—");
                row(Tr(L"Threat"), thr, bad ? clr::Red : clr::TextDim);
            }
        }
        if (!h->certIssuer.empty())
            row(Tr(L"Certificate"), h->certIssuer + (h->certSubject.empty() ? L"" : (L" • CN=" + h->certSubject)) +
                              (h->certSelfSigned ? Tr(L" • self-signed") : L""),
                h->certSelfSigned || h->certExpired ? clr::Orange : clr::TextDim);
        row(Tr(L"Time"),    h->TimeText() + L"  •  " + Tr(L"duration") + L" " + h->DurationText(), clr::TextDim);
        row(Tr(L"Data"),     L"↓ " + FormatBytes(h->bytesIn) + L"   ↑ " + FormatBytes(h->bytesOut), clr::TextDim);
        row(Tr(L"Path"),      h->path, clr::TextDim);
        row(Tr(L"Risk note"),h->riskReason, RiskColor(h->risk));
    }

    if (y + S(46) < card.bottom - S(6)) {
        RECT g = { x, card.bottom - S(44), splitX - S(10), card.bottom - S(8) };
        RECT gl = { g.left, g.top - S(14), g.right, g.top };
        const RateHistory* rh = m_hist.AppRates(graphProc);
        const unsigned long long spanMs = rh ? rh->SpanMs() : 0;
        wchar_t glb[260];
        swprintf(glb, 260, Tr(L" last %s  (↓ blue / ↑ purple)"),
                 spanMs >= 1000 ? FormatDurationShort(spanMs / 1000).c_str() : L"—");
        p.Text(graphProc + glb, gl, m_fSmall, clr::TextFaint,
               DT_LEFT | DT_BOTTOM | DT_SINGLELINE);
        DrawMiniGraph(p, g, rh, m_isAdmin);
    }

    RECT ai = { splitX + S(8), card.top + S(8), card.right - S(12), card.bottom - S(8) };
    p.Line(splitX, card.top + S(8), splitX, card.bottom - S(8), clr::Border);

    RECT aiHead = { ai.left + S(6), ai.top, ai.right, ai.top + S(20) };
    std::wstring head = m_aiTitle.empty() ? Tr(L"AI / Analysis") : m_aiTitle;
    if (m_aiKeyMissing) head += Tr(L"   [no API key — offline engine]");
    p.Text(head, aiHead, m_fBold, m_aiKeyMissing ? clr::Yellow : clr::Cyan,
           DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);

    std::wstring body;
    {
        std::lock_guard<std::mutex> lk(m_aiMtx);
        body = m_aiBusy ? Tr(L"Analyzing…") : m_aiText;
    }
    if (body.empty())
        body = std::wstring(Tr(L"The 'AI Analyze' button (or Enter) analyzes the selected row.\n")) +
               Tr(L"Ctrl+Enter: batch-analyzes the riskiest connections.\n\n") +
               Tr(L"Without an API key a detailed offline heuristic analysis is shown instead.");

    const bool aiActions = (!m_aiBusy && !m_aiText.empty() && !m_lastAiPrompt.empty());
    RECT aiBody = { ai.left + S(6), ai.top + S(22), ai.right - S(6),
                    ai.bottom - (aiActions ? S(38) : 0) };

    const int aiTextH = p.MeasureWrapped(body, m_fUi, aiBody.right - aiBody.left);
    m_aiMaxScroll = (std::max)(0, aiTextH - (int)(aiBody.bottom - aiBody.top));
    if (m_aiScroll > m_aiMaxScroll) m_aiScroll = m_aiMaxScroll;
    if (m_aiScroll < 0) m_aiScroll = 0;

    HRGN clip = CreateRectRgn(aiBody.left, aiBody.top, aiBody.right, aiBody.bottom);
    SelectClipRgn(p.dc(), clip);
    RECT tr2 = aiBody;
    tr2.top -= m_aiScroll;
    tr2.bottom = tr2.top + aiTextH + S(40);
    p.Text(body, tr2, m_fUi, clr::TextDim, DT_LEFT | DT_TOP | DT_WORDBREAK | DT_EDITCONTROL);
    SelectClipRgn(p.dc(), nullptr);
    DeleteObject(clip);

    m_aiBtn1 = m_aiBtn2 = m_aiBtn3 = RECT{};
    if (aiActions) {
        const int gap = S(6), bw = (ai.right - ai.left - S(12) - gap * 2) / 3, bh2 = S(26);
        m_aiBtn1 = { ai.left + S(6), ai.bottom - S(32), ai.left + S(6) + bw, ai.bottom - S(32) + bh2 };
        m_aiBtn2 = { m_aiBtn1.right + gap, m_aiBtn1.top, m_aiBtn1.right + gap + bw, m_aiBtn1.bottom };
        m_aiBtn3 = { m_aiBtn2.right + gap, m_aiBtn1.top, m_aiBtn2.right + gap + bw, m_aiBtn1.bottom };
        const wchar_t* lbls[3] = { Tr(L"Why is this suspicious?"), Tr(L"What should I do?"), Tr(L"Deviation from normal?") };
        RECT* btns[3] = { &m_aiBtn1, &m_aiBtn2, &m_aiBtn3 };
        for (int i = 0; i < 3; ++i) {
            p.FillRoundRect(*btns[i], S(6), m_hotBtn == 601 + i ? clr::SurfaceHi : clr::Surface);
            p.StrokeRoundRect(*btns[i], S(6), clr::Border);
            p.Text(lbls[i], *btns[i], m_fSmallBold, clr::Text,
                   DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
        }
    }
}

void App::ShowOverlay(Overlay o) {
    m_overlay = o;
    m_ovBtn1 = m_ovBtn2 = m_ovBtn3 = RECT{};
    m_overlayDrawn = false;
    InvalidateRect(m_hwnd, nullptr, FALSE);
}

void App::DrawOverlayButton(Painter& p, RECT& r, const std::wstring& label,
                            bool primary, bool danger) {
    p.FillRoundRect(r, S(8), primary ? clr::Accent : (danger ? clr::Red : clr::SurfaceHi));
    p.StrokeRoundRect(r, S(8), danger ? clr::Red : (primary ? clr::Accent : clr::Border));
    RECT tr = { r.left + S(10), r.top, r.right - S(10), r.bottom };
    p.Text(label, tr, m_fBold, primary || danger ? RGB(255, 255, 255) : clr::Text,
           DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
}

void App::DrawOverlay(Painter& p) {
    RECT full;
    GetClientRect(m_hwnd, &full);
    p.FillRectAlpha(full, RGB(0, 0, 0), 185);

    const int w = S(560), h = S(m_overlay == Overlay::Welcome ? 470 : 500);
    RECT card = { (full.right - w) / 2, (full.bottom - h) / 2,
                  (full.right - w) / 2 + w, (full.bottom - h) / 2 + h };
    p.FillRoundRect(card, S(12), clr::Surface);
    p.StrokeRoundRect(card, S(12), clr::Accent);

    int y = card.top + S(26);
    RECT t = { card.left + S(28), y, card.right - S(28), y + S(40) };
    p.Text(Tr(L"NETLURKER"), t, m_fHuge, clr::Accent, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    y += S(44);
    RECT sub = { card.left + S(28), y, card.right - S(28), y + S(24) };
    p.Text(Tr(L"WINDOWS NETWORK INTELLIGENCE"), sub, m_fTitle, clr::Text,
           DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    y += S(30);

    if (m_overlay == Overlay::Welcome) {
        struct Row { const wchar_t* t; COLORREF c; };
        const Row rows[] = {
            { Tr(L"✓  Real-time network monitoring"),          clr::Green },
            { Tr(L"✓  Process identification (signature + publisher)"),  clr::Green },
            { Tr(L"✓  DNS / TLS / RDAP intelligence"),      clr::Green },
            { Tr(L"✓  Threat intelligence (4 sources)"),     clr::Green },
            { Tr(L"✓  AI-assisted investigation"),              clr::Green },
        };
        for (const auto& r : rows) {
            RECT rr = { card.left + S(28), y, card.right - S(28), y + S(22) };
            p.Text(r.t, rr, m_fUi, r.c, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
            y += S(24);
        }
        y += S(8);
        RECT pr = { card.left + S(28), y, card.right - S(28), y + S(20) };
        p.Text(Tr(L"Privacy: your network data is processed on this device; no telemetry, no analytics, no account."),
               pr, m_fSmall, clr::TextFaint, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_WORDBREAK);
        y += S(26);
        if (!m_isAdmin) {
            RECT ar = { card.left + S(28), y, card.right - S(28), y + S(20) };
            p.Text(Tr(L"Tip: admin rights unlock per-connection rates, RTT, and DLL module detection (elevate from the warning in the status bar)."),
                   ar, m_fSmall, clr::Yellow, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_WORDBREAK);
            y += S(24);
        }
        y += S(10);
        const int bw = (w - S(28) * 2 - S(12) * 2) / 3;
        m_ovBtn1 = { card.left + S(28), y, card.left + S(28) + bw, y + S(38) };
        m_ovBtn2 = { m_ovBtn1.right + S(12), y, m_ovBtn1.right + S(12) + bw, y + S(38) };
        m_ovBtn3 = { m_ovBtn2.right + S(12), y, card.right - S(28), y + S(38) };
        DrawOverlayButton(p, m_ovBtn1, Tr(L"START MONITORING"), true, false);
        DrawOverlayButton(p, m_ovBtn2, Tr(L"DEMO MODE"), false, false);
        DrawOverlayButton(p, m_ovBtn3, Tr(L"PRIVACY"), false, false);
    } else {
        struct PRow { const wchar_t* t; COLORREF c; };
        const PRow rows[] = {
            { Tr(L"✓  Network data is processed locally"),    clr::Green },
            { Tr(L"✓  No telemetry"),                      clr::Green },
            { Tr(L"✓  No analytics / ads"),              clr::Green },
            { Tr(L"✓  No account or registration"),          clr::Green },
        };
        for (const auto& r : rows) {
            RECT rr = { card.left + S(28), y, card.right - S(28), y + S(22) };
            p.Text(r.t, rr, m_fUi, r.c, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
            y += S(24);
        }
        y += S(6);
        RECT hdr = { card.left + S(28), y, card.right - S(28), y + S(20) };
        p.Text(Tr(L"External services are only queried when you enable them:"),
               hdr, m_fSmallBold, clr::TextDim, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
        y += S(22);
        struct SRow { std::wstring name; std::wstring state; };
        std::vector<SRow> svc = {
            { Tr(L"IP geolocation (ip-api.com)"),  m_geoOnline ? Tr(L"ON") : Tr(L"OFF") },
            { Tr(L"Threat intelligence (AbuseIPDB + blacklists + CIRCL)"),
              m_threatOnline ? Tr(L"ON") : Tr(L"OFF") },
            { Tr(L"RDAP ownership (rdap.org)"), m_rdapOnline ? Tr(L"ON") : Tr(L"OFF") },
            { Tr(L"VirusTotal (only if a key is set)"),
              m_vtOnline ? Tr(L"ON") : Tr(L"OFF") },
            { Tr(L"TLS certificate (single ClientHello to target)"),
              m_threatOnline ? Tr(L"ON") : Tr(L"OFF") },
            { Tr(L"HTTP banner (single HEAD to target)"), m_bannerOnline ? Tr(L"ON") : Tr(L"OFF") },
        };
        for (const auto& srow : svc) {
            RECT nr = { card.left + S(28), y, card.right - S(90), y + S(18) };
            p.Text(srow.name, nr, m_fSmall, clr::TextDim, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
            RECT sr = { card.right - S(90), y, card.right - S(28), y + S(18) };
            p.Text(srow.state, sr, m_fSmallBold,
                   srow.state == Tr(L"ON") ? clr::Green : clr::TextFaint,
                   DT_RIGHT | DT_VCENTER | DT_SINGLELINE);
            y += S(19);
        }
        y += S(16);
        m_ovBtn1 = { card.left + w / 2 - S(70), y, card.left + w / 2 + S(70), y + S(36) };
        m_ovBtn2 = m_ovBtn3 = RECT{};
        DrawOverlayButton(p, m_ovBtn1, Tr(L"GOT IT"), true, false);
    }
    m_overlayDrawn = true;
}

void App::EnterDemo() {
    if (m_demo) return;
    m_demo = true;
    m_paused = false;
    m_lastDemoTick = 0;
    m_demoRows.clear();
    RebuildDemoRows();
    Toast(Tr(L"Demo mode on — running with sample data (press Ctrl+D to exit)"), clr::Cyan);
    InvalidateRect(m_hwnd, nullptr, FALSE);
}

void App::ExitDemo() {
    m_demo = false;
    m_demoRows.clear();
    Toast(Tr(L"Demo mode off — loading real system data…"), clr::Green);
    Tick(true);
}

static Conn DemoConn(const wchar_t* proc, const wchar_t* path, const wchar_t* pub,
                     SignState sign, DWORD pid, Proto proto, const wchar_t* lip,
                     unsigned short lp, const wchar_t* rip, unsigned short rp,
                     const wchar_t* cc, const wchar_t* country, const wchar_t* city,
                     const wchar_t* org, const wchar_t* asn, const wchar_t* host,
                     const wchar_t* domain, const wchar_t* banner, const wchar_t* mod,
                     int threat, const wchar_t* dnsbl, const wchar_t* certIssuer,
                     const wchar_t* rdapOrg, int vtMal, int vtTot, bool hosting,
                     Risk risk, int riskScore, const wchar_t* reason) {
    Conn c;
    c.proto = proto;
    c.localIp = lip;
    c.remoteIp = rip;
    c.localPort = lp;
    c.remotePort = rp;
    c.state = (proto == Proto::TCP4 || proto == Proto::TCP6) ? MIB_TCP_STATE_ESTAB : 0;
    c.pid = pid;
    c.procName = proc;
    c.procPath = path;
    c.publisher = pub;
    c.sign = sign;
    c.user = L"user";
    c.country = country;
    c.countryCode = cc;
    c.city = city;
    c.org = org;
    c.asn = asn;
    c.host = host;
    c.domain = domain;
    c.banner = banner;
    c.module = mod;
    c.threatScore = threat;
    c.threatDnsbl = dnsbl;
    c.certIssuer = certIssuer;
    c.rdapOrg = rdapOrg;
    c.vtMalicious = vtMal;
    c.vtTotal = vtTot;
    c.isHosting = hosting;
    c.isRemotePublic = true;
    c.risk = risk;
    c.riskScore = riskScore;
    c.riskReason = reason;
    c.rttMs = 10 + (unsigned)(pid % 40);
    c.ageMs = 4000 + pid * 1000;
    c.ageExact = true;
    return c;
}

void App::RebuildDemoRows() {
    const unsigned long long now = NowMs();
    if (!m_lastDemoTick) m_lastDemoTick = now;
    const double dt = (double)(now - m_lastDemoTick) / 1000.0;
    m_lastDemoTick = now;
    const double phase = (double)(now % 60000) / 60000.0 * 6.2831853;
    const double wave = 0.5 + 0.5 * sin(phase);

    std::vector<Conn> rows;

    for (int i = 0; i < 4; ++i) {
        const wchar_t* hosts[] = { L"142.250.186.46", L"142.250.189.14", L"104.244.42.193", L"151.101.1.69" };
        const wchar_t* cc[4] = { L"US", L"US", L"US", L"NL" };
        const wchar_t* cn[4] = { Tr(L"United States"), Tr(L"United States"),
                                 Tr(L"United States"), L"Hollanda" };
        const wchar_t* og[4] = { L"Google LLC", L"Google LLC", L"Fastly, Inc.", L"Fastly, Inc." };
        const wchar_t* ho[4] = { L"www.google.com", L"gstatic.com", L"x.com", L"reddit.com" };
        const wchar_t* dom[4] = { L"google.com", L"gstatic.com", L"x.com", L"reddit.com" };
        const wchar_t* certs[4] = { L"Google Trust Services", L"Google Trust Services",
                                    L"DigiCert Inc", L"DigiCert Inc" };
        rows.push_back(DemoConn(L"chrome.exe", L"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                                L"Google LLC", SignState::Signed, 4820, Proto::TCP4, L"192.168.1.42",
                                (unsigned short)(51000 + i), hosts[i], 443,
                                cc[i], cn[i], L"", og[i], L"AS15169", ho[i], dom[i],
                                L"", L"chrome.dll", 0, L"—", certs[i], og[i], 0, 0, false,
                                Risk::Safe, 4, L""));
    }

    rows.push_back(DemoConn(L"svchost.exe", L"C:\\Windows\\System32\\svchost.exe",
                            L"Microsoft Corporation", SignState::SignedMicrosoft, 1180, Proto::UDP4,
                            L"192.168.1.42", 51337, L"8.8.8.8", 53,
                            L"US", Tr(L"United States"), L"Mountain View",
                            L"Google LLC", L"AS15169", L"dns.google", L"dns.google",
                            L"", L"dnsapi.dll", 0, L"—", L"", L"Google LLC", 0, 0, false,
                            Risk::Safe, 2, L""));

    rows.push_back(DemoConn(L"svchost.exe", L"C:\\Windows\\System32\\svchost.exe",
                            L"Microsoft Corporation", SignState::SignedMicrosoft, 1180, Proto::TCP4,
                            L"192.168.1.42", 51338, L"23.216.147.64", 443,
                            L"US", Tr(L"United States"), L"",
                            L"Akamai Technologies", L"AS16625", L"a767.dscd.akamai.net",
                            L"windowsupdate.com", L"", L"", 0, L"—", L"Microsoft Azure RSA TLS Issuing CA 04",
                            L"Akamai Technologies", 0, 0, false,
                            Risk::Safe, 6, L""));

    {
        Conn c = DemoConn(L"updater.exe", L"C:\\Users\\user\\AppData\\Local\\Temp\\updater.exe",
                          L"", SignState::Unsigned, 9312, Proto::TCP4, L"192.168.1.42",
                          51944, L"45.155.205.86", 4444,
                          L"NL", L"Hollanda", L"Amsterdam", L"M247 Europe SRL", L"AS9009",
                          L"", L"", L"", L"",
                          67, L"spamhaus: SBL, blocklist.de", L"", L"M247 Europe SRL",
                          9, 94, true, Risk::Danger, 88,
                          Tr(L"Unsigned process is registered to auto-start (persistence, T1547)"));
        c.rdapCidr = L"45.155.204.0/22";
        c.rdapAbuse = L"abuse@m247.com";
        c.vtSuspicious = 12;
        c.vtReputation = -3;
        c.threatTor = false;
        c.isNew = true;
        c.ageMs = 45000;
        c.ageExact = true;
        rows.push_back(c);
    }

    rows.push_back(DemoConn(L"winsvchost.exe", L"C:\\Users\\user\\AppData\\Roaming\\winsvchost.exe",
                            L"", SignState::Invalid, 8271, Proto::TCP4, L"192.168.1.42",
                            51471, L"103.148.244.178", 3333,
                            L"SG", L"Singapur", L"", L"Host Universal Pty Ltd", L"AS136557",
                            L"", L"", L"", L"",
                            38, L"", L"", L"Host Universal Pty Ltd", 2, 89, true,
                            Risk::Warn, 56,
                            Tr(L"Destination port does not belong to a known service (T1571)")));

    {
        Conn c = DemoConn(L"syncsvc.exe", L"C:\\Users\\user\\AppData\\Local\\Programs\\syncsvc\\syncsvc.exe",
                          L"Contoso Software Inc.", SignState::Signed, 6630, Proto::TCP4,
                          L"192.168.1.42", 51220, L"185.220.101.34", 8080,
                          L"DE", L"Almanya", L"", L"Contoso Hosting GmbH", L"AS200052",
                          L"", L"", L"Apache/2.2.15 (EOL)", L"",
                          0, L"—", L"", L"Contoso Hosting GmbH", 0, 0, true,
                          Risk::Warn, 47,
                          Tr(L"Repeated connections to the same target every ~60 s (C2 beacon pattern, T1071)"));
        rows.push_back(c);
    }

    rows.push_back(DemoConn(L"telemetry.exe", L"C:\\Program Files\\OEM\\telemetry.exe",
                            L"OEM Inc.", SignState::Signed, 5512, Proto::TCP4, L"192.168.1.42",
                            51198, L"13.107.4.50", 443,
                            L"US", Tr(L"United States"), L"Redmond",
                            L"Microsoft Corporation", L"AS8075", L"", L"telemetry.example.com",
                            L"", L"", 0, L"—", L"Microsoft Azure RSA TLS Issuing CA 01",
                            L"Microsoft Corporation", 0, 0, false,
                            Risk::Info, 24,
                            Tr(L"Destination IP is manually redirected in the hosts file (may have been modified by software)")));
    rows[rows.size() - 1].hostsRedirect = true;

    rows.push_back(DemoConn(L"GameClient.exe", L"D:\\Oyunlar\\GameClient\\GameClient.exe",
                            L"GameStudio Ltd.", SignState::Signed, 7144, Proto::UDP4, L"192.168.1.42",
                            6112, L"162.254.197.40", 27015,
                            L"DE", L"Almanya", L"Frankfurt", L"Valve Corporation", L"AS32590",
                            L"", L"steamcommunity.com", L"", L"",
                            0, L"—", L"", L"Valve Corporation", 0, 0, false,
                            Risk::Safe, 3, L""));

    static unsigned long long s_base[12];
    const double rateFactor = 20.0 + 45.0 * wave;
    for (size_t i = 0; i < rows.size() && i < 12; ++i) {
        if (!s_base[i]) s_base[i] = now;
        const double secs = (double)(now - s_base[i]) / 1000.0;
        if (secs > 600.0) s_base[i] = now - 300000;
        rows[i].rateIn  = (i % 3 == 0) ? rateFactor * 1024.0 : rateFactor * 512.0;
        rows[i].rateOut = rateFactor * 128.0;
        rows[i].bytesIn  += (unsigned long long)(rows[i].rateIn  * dt);
        rows[i].bytesOut += (unsigned long long)(rows[i].rateOut * dt);
    }
    m_demoRows.swap(rows);
}

void App::RebuildDemoApps() {
    std::vector<AppRow> apps;
    for (const auto& c : m_demoRows) {
        AppRow* row = nullptr;
        for (auto& a : apps) if (a.pid == c.pid) { row = &a; break; }
        if (!row) {
            apps.push_back(AppRow{});
            row = &apps.back();
            row->pid = c.pid;
            row->name = c.procName;
            row->path = c.procPath;
            row->publisher = c.publisher;
            row->sign = c.sign;
            row->user = c.user;
            row->startTime = NowMs() - 600000;
        }
        row->conns++;
        if (c.isRemotePublic) row->publicConns++;
        row->rateIn += c.rateIn;
        row->rateOut += c.rateOut;
        row->bytesIn += c.bytesIn;
        row->bytesOut += c.bytesOut;
        row->cpu = 1.0 + (double)(c.pid % 17);
        row->ram = (unsigned long long)(40 + (c.pid % 300)) * 1024 * 1024;
        if (c.riskScore > row->riskScore) {
            row->riskScore = c.riskScore;
            row->risk = c.risk;
            row->riskReason = c.riskReason;
        }
        if (!c.domain.empty() && std::find(row->domains.begin(), row->domains.end(), c.domain) == row->domains.end() &&
            row->domains.size() < 8)
            row->domains.push_back(c.domain);
    }
    for (auto& a : apps) {
        if (!a.domains.empty()) {
            a.domain = a.domains[0];
            if (a.domains.size() > 1) a.domain += L" +" + std::to_wstring(a.domains.size() - 1);
        }
    }
    m_apps.swap(apps);
}

static void FwCollect(const std::shared_ptr<FwState>& st) {
    std::vector<FwRule> rules;
    const bool ok = FwListNetLurkerRules(rules);
    std::unordered_set<std::wstring> ips;
    std::unordered_map<std::wstring, std::wstring> names;
    if (ok)
        for (const auto& r : rules)
            if (r.enabled && !r.remoteIp.empty()) {
                ips.insert(r.remoteIp);
                names[r.remoteIp] = r.name;
            }
    {
        std::lock_guard<std::mutex> lk(st->m);
        st->checked = ok;
        if (ok) { st->ips.swap(ips); st->names.swap(names); }
    }
    st->busy = false;
}

void App::RefreshFirewallRules(bool force) {
    const unsigned long long now = NowMs();
    if (force) {
        while (m_fw->busy.load()) Sleep(10);
        m_fw->busy = true;
        FwCollect(m_fw);
        m_lastFwTick = now;
    } else {
        if (m_lastFwTick && now - m_lastFwTick < 10000) return;
        m_lastFwTick = now;
        if (!m_fw->busy.exchange(true)) {
            auto st = m_fw;
            std::thread([st] { FwCollect(st); }).detach();
        }
    }
    std::lock_guard<std::mutex> lk(m_fw->m);
    m_fwChecked = m_fw->checked;
    m_blockedIps = m_fw->ips;
}

void App::UnblockSelectedIp() {
    std::wstring ip;
    if (const Conn* c = SelectedConn())           ip = c->remoteIp;
    else if (const HistEntry* h = SelectedHist()) ip = h->remoteIp;
    if (ip.empty() || !m_blockedIps.count(ip)) return;
    ScopedTimerPause pause(m_hwnd, 1, m_interval);
    std::wstring ruleName = FwRuleNameFor(ip);
    {
        std::lock_guard<std::mutex> lk(m_fw->m);
        auto it = m_fw->names.find(ip);
        if (it != m_fw->names.end()) ruleName = it->second;
    }
    if (FwRemoveRule(ruleName)) {
        RefreshFirewallRules(true);
        if (m_blockedIps.count(ip))
            Toast(Tr(L"Firewall rule still present for ") + ip, clr::Orange);
        else
            Toast(Tr(L"Firewall block removed: ") + ip, clr::Green);
    } else {
        Toast(Tr(L"Could not remove the firewall rule (administrator rights required): ") + ip, clr::Red);
    }
}

void App::PushRateSample(double in, double out) {
    const unsigned long long now = NowMs();
    m_rateHist.push_back(RateSample{ now, in, out });
    while (!m_rateHist.empty() && now - m_rateHist.front().ts > kRateWindowMs)
        m_rateHist.pop_front();
}

void App::NoteNewConnections() {
    for (const auto& c : m_rows) {
        if (!c.isNew || !c.isRemotePublic) continue;
        m_anomNew[c.procName.empty() ? L"?" : c.procName]++;
    }
}

void App::TickAnomaly() {
    const unsigned long long now = NowMs();
    if (!m_lastAnomTick) m_lastAnomTick = now;
    const double dtMin = (double)(now - m_lastAnomTick) / 60000.0;
    if (dtMin < 0.25) return;
    m_lastAnomTick = now;

    std::unordered_map<std::wstring, int> counts;
    counts.swap(m_anomNew);
    for (const auto& c : m_rows) {
        if (!c.isRemotePublic) continue;
        std::wstring name = c.procName.empty() ? L"?" : c.procName;
        if (!counts.count(name)) counts[name] = 0;
    }

    for (auto& kv : m_anomStats) kv.second.lastRate = 0;
    for (auto& kv : counts) {
        const double rate = (double)kv.second / dtMin;
        auto it = m_anomStats.find(kv.first);
        if (it == m_anomStats.end()) {
            AnomStat st;
            st.ema = rate;
            st.n = 1;
            st.lastRate = rate;
            m_anomStats[kv.first] = st;
            continue;
        }
        AnomStat& st = it->second;
        const double a = 0.15;
        st.var = (1 - a) * st.var + a * (rate - st.ema) * (rate - st.ema);
        st.ema = (1 - a) * st.ema + a * rate;
        st.n++;
        st.lastRate = rate;
    }
    m_anomRates.clear();
    for (auto& kv : m_anomStats) m_anomRates.push_back({ kv.first, kv.second.lastRate });

    for (auto& kv : m_anomStats) {
        AnomStat& st = kv.second;
        const bool warm = st.n >= 24;
        const double std = sqrt(st.var);
        const bool outlier = warm && st.lastRate > 6.0 &&
                             (st.lastRate > st.ema + 3.0 * std || st.lastRate > st.ema * 3.0);
        auto it = m_anomAlerts.find(kv.first);
        if (outlier) {
            const int pct = st.ema > 0.5 ? (int)((st.lastRate / st.ema - 1.0) * 100.0) : 0;
            if (it == m_anomAlerts.end()) {
                AnomAlert al;
                al.name = kv.first;
                al.baseline = st.ema;
                al.current = st.lastRate;
                al.pct = pct;
                al.t = now;
                m_anomAlerts[kv.first] = al;
            } else {
                it->second.baseline = st.ema;
                it->second.current = st.lastRate;
                it->second.pct = pct;
                it->second.t = now;
            }

            auto& al = m_anomAlerts[kv.first];
            if (m_notify && now - al.warned > 300000) {
                al.warned = now;
                std::wstring body = al.name + Tr(L" process is connecting ") +
                                    std::to_wstring((std::max)(0, pct)) +
                                    Tr(L"% more connections than usual.\nBaseline: ") +
                                    std::to_wstring((int)al.baseline) + Tr(L" conn/min → now: ") +
                                    std::to_wstring((int)al.current) + Tr(L" conn/min");
                Notify(Tr(L"NetLurker: behavioral anomaly"), body, true);
            }
        } else if (it != m_anomAlerts.end() && now - it->second.t > 120000) {
            m_anomAlerts.erase(it);
        }
    }
}

void App::LoadAnomalyBaseline() {
    std::wstring path = AppDataDir() + L"\\baseline2.tsv";
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    std::string raw;
    char buf[4096];
    DWORD got = 0;
    while (ReadFile(h, buf, sizeof(buf), &got, nullptr) && got) raw.append(buf, got);
    CloseHandle(h);
    std::wstring text = Widen(raw);
    size_t p = 0;
    while (p < text.size()) {
        size_t e = text.find(L'\n', p);
        if (e == std::wstring::npos) e = text.size();
        std::wstring line = text.substr(p, e - p);
        p = e + 1;
        if (!line.empty() && line.back() == L'\r') line.pop_back();
        size_t t1 = line.find(L'\t');
        if (t1 == std::wstring::npos) continue;
        size_t t2 = line.find(L'\t', t1 + 1);
        if (t2 == std::wstring::npos) continue;
        AnomStat st;
        st.ema = _wtof(line.substr(t1 + 1, t2 - t1 - 1).c_str());
        st.var = _wtof(line.substr(t2 + 1).c_str());
        st.n = 24;
        if (st.ema > 0) m_anomStats[line.substr(0, t1)] = st;
    }
}

void App::SaveAnomalyBaseline() {
    std::wstring out;
    for (const auto& kv : m_anomStats) {
        if (kv.second.n < 24) continue;
        wchar_t line[256];
        swprintf(line, 256, L"%s\t%.2f\t%.2f\n", kv.first.c_str(), kv.second.ema, kv.second.var);
        out += line;
    }
    if (out.empty()) return;
    std::wstring path = AppDataDir() + L"\\baseline2.tsv";
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    std::string bytes = Narrow(out);
    DWORD wr = 0;
    WriteFile(h, bytes.data(), (DWORD)bytes.size(), &wr, nullptr);
    CloseHandle(h);
}

void App::DrawGraph(Painter& p) {
    RECT area = { m_rcTable.left, m_rcTableHead.top, m_rcTable.right, m_rcTable.bottom };
    p.FillRect(area, clr::Bg);

    struct GNode {
        std::wstring label;
        double bytes = 0;
        int risk = 0;
        std::wstring country;
    };
    struct GEdge { std::wstring proc; std::wstring ep; double bytes; int risk; };

    std::unordered_map<std::wstring, int> pIdx, eIdx;
    std::vector<GNode> procs, eps;
    std::vector<GEdge> edges;
    for (const auto& c : m_rows) {
        const std::wstring pname = c.procName.empty() ? L"?" : c.procName;
        auto pit = pIdx.find(pname);
        if (pit == pIdx.end()) {
            pIdx[pname] = (int)procs.size();
            GNode n; n.label = pname;
            procs.push_back(n);
        }
        const std::wstring elabel = c.domain.empty()
            ? (c.host.empty() || c.host == L"—" ? c.remoteIp : c.host) : c.domain;
        auto eit = eIdx.find(elabel);
        if (eit == eIdx.end()) {
            eIdx[elabel] = (int)eps.size();
            GNode n; n.label = elabel;
            n.country = c.countryCode;
            eps.push_back(n);
        }
        edges.push_back({ pname, elabel, (double)(c.bytesIn + c.bytesOut), c.riskScore });
        GNode& pn = procs[pIdx[pname]];
        GNode& en = eps[eIdx[elabel]];
        pn.bytes += (double)(c.bytesIn + c.bytesOut);
        en.bytes += (double)(c.bytesIn + c.bytesOut);
        if (c.riskScore > pn.risk) pn.risk = c.riskScore;
        if (c.riskScore > en.risk) en.risk = c.riskScore;
        if (!c.countryCode.empty() && c.countryCode != L"—") en.country = c.countryCode;
    }
    auto byBytes = [](const GNode& a, const GNode& b) { return a.bytes > b.bytes; };
    std::sort(procs.begin(), procs.end(), byBytes);
    std::sort(eps.begin(), eps.end(), byBytes);
    if (procs.size() > 14) procs.resize(14);
    if (eps.size() > 26) eps.resize(26);
    std::unordered_set<std::wstring> pKeep, eKeep;
    for (const auto& n : procs) pKeep.insert(n.label);
    for (const auto& n : eps) eKeep.insert(n.label);
    std::vector<GEdge> kept;
    for (const auto& e : edges)
        if (pKeep.count(e.proc) && eKeep.count(e.ep)) kept.push_back(e);
    edges.swap(kept);

    std::unordered_map<std::wstring, int> pRow, eRow;
    for (size_t i = 0; i < procs.size(); ++i) pRow[procs[i].label] = (int)i;
    for (size_t i = 0; i < eps.size(); ++i) eRow[eps[i].label] = (int)i;

    const int pad = S(16);
    const int W = area.right - area.left - pad * 2;
    const int H = area.bottom - area.top - pad * 2;
    const int leftX = area.left + pad;
    const int leftW = (std::min)(S(320), (W * 2) / 5);
    const int rightX = area.left + pad + W - (std::min)(S(380), (W * 2) / 5);
    const int procH = (std::min)(S(42), (std::max)(S(26), (H - S(60)) / (int)(std::max<size_t>(1, procs.size()))));
    const int epH   = (std::min)(S(36), (std::max)(S(22), (H - S(60)) / (int)(std::max<size_t>(1, eps.size()))));
    const int topY = area.top + pad + S(38);

    RECT t = { area.left + pad, area.top + S(6), area.right - pad, area.top + S(30) };
    wchar_t hbuf[256];
    swprintf(hbuf, 256, Tr(L"Network graph — %d processes, %d targets, %d flows"),
             (int)procs.size(), (int)eps.size(), (int)edges.size());
    p.Text(hbuf, t, m_fBold, clr::Text, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);

    auto riskColor = [](int score) -> COLORREF {
        if (score >= 70) return clr::Red;
        if (score >= 45) return clr::Orange;
        if (score >= 20) return clr::Yellow;
        return clr::Green;
    };
    auto nodeRect = [&](int i, bool isProc) -> RECT {
        int x = isProc ? leftX : rightX;
        int y = topY + i * (isProc ? procH : epH);
        int w = isProc ? leftW : (area.right - pad - rightX);
        return { x, y, x + w, y + (isProc ? procH - S(10) : epH - S(6)) };
    };

    for (const auto& e : edges) {
        auto a = pRow.find(e.proc), b = eRow.find(e.ep);
        if (a == pRow.end() || b == eRow.end()) continue;
        RECT ra = nodeRect(a->second, true);
        RECT rb = nodeRect(b->second, false);
        POINT p1 = { ra.right, (ra.top + ra.bottom) / 2 };
        POINT p2 = { rb.left, (rb.top + rb.bottom) / 2 };
        COLORREF c = (e.risk >= 20) ? riskColor(e.risk) : clr::Border;
        const float wpx = (e.bytes > 200 * 1024) ? 2.0f : 1.0f;
        if (e.risk < 20) {
            p.Line(p1.x, p1.y, p2.x, p2.y, c, wpx);
        } else {
            const int bow = (p2.x - p1.x) / 4;
            std::vector<POINT> pts = { p1, { p1.x + bow, p1.y },
                                       { p2.x - bow, p2.y }, p2 };
            p.Polyline(pts, c, wpx);
        }
    }

    for (size_t i = 0; i < procs.size(); ++i) {
        RECT r = nodeRect((int)i, true);
        p.FillRoundRect(r, S(6), clr::Surface);
        p.StrokeRoundRect(r, S(6), riskColor(procs[i].risk), 1.0f);
        RECT tr = { r.left + S(8), r.top, r.right - S(8), r.bottom };
        p.Text(procs[i].label, tr, m_fSmallBold, clr::Text,
               DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
    }
    for (size_t i = 0; i < eps.size(); ++i) {
        RECT r = nodeRect((int)i, false);
        p.FillRoundRect(r, S(6), clr::SurfaceHi);
        p.StrokeRoundRect(r, S(6), riskColor(eps[i].risk), 1.0f);
        std::wstring l = eps[i].label;
        if (!eps[i].country.empty()) l += L"  [" + eps[i].country + L"]";
        RECT tr = { r.left + S(8), r.top, r.right - S(8), r.bottom };
        p.Text(l, tr, m_fSmall, clr::Text,
               DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
    }
    if (m_rows.empty()) {
        RECT er = area;
        p.Text(Tr(L"Waiting for live connections to draw the graph… (try demo mode with Ctrl+D)"),
               er, m_fUi, clr::TextFaint, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    }
    RECT lg = { area.left + pad, area.bottom - S(22), area.right - pad, area.bottom - S(4) };
    p.Text(Tr(L"Color: green = normal · yellow = info · orange = suspicious · red = critical   (Thickness: data flow)"),
           lg, m_fSmall, clr::TextFaint, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
}

void App::DrawHelp(Painter& p) {
    RECT full;
    GetClientRect(m_hwnd, &full);
    p.FillRectAlpha(full, RGB(0, 0, 0), 170);

    const int w = S(720), h = S(486);
    RECT card = { (full.right - w) / 2, (full.bottom - h) / 2,
                  (full.right - w) / 2 + w, (full.bottom - h) / 2 + h };
    p.FillRoundRect(card, S(10), clr::Surface);
    p.StrokeRoundRect(card, S(10), clr::Accent);

    RECT t = { card.left + S(22), card.top + S(14), card.right - S(22), card.top + S(44) };
    p.Text(Tr(L"NetLurker — shortcuts & tips"), t, m_fBig, clr::Text, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    RECT sub = { card.left + S(22), card.top + S(42), card.right - S(22), card.top + S(62) };
    p.Text(Tr(L"Close with F1 or Esc"), sub, m_fSmall, clr::TextFaint, DT_LEFT | DT_VCENTER | DT_SINGLELINE);

    struct HelpRow { const wchar_t* key; const wchar_t* what; };
    static const HelpRow rows[] = {
        { L"1 2 3 4 / Tab",  L"Tabs: Connections · Applications · History · Summary · Network graph" },
        { L"↑ ↓ PgUp PgDn",  L"Move between rows (Home / End: first / last)" },
        { L"Enter",          L"Analyze the selected connection with AI (double-click does the same)" },
        { L"Ctrl+Enter",     L"Batch-analyze the riskiest connections" },
        { L"Del",            L"Force-terminate the process (one click, no confirmation)" },
        { L"Shift+Del / Ctrl+K", L"Terminate the process tree (including child processes)" },
        { L"Ctrl+P",         L"Suspend / resume the process" },
        { L"Space",         L"Pause / resume monitoring" },
        { L"F5",             L"Refresh now" },
        { L"Ctrl+F",         L"Focus the search box   ·   Esc: clear the filter" },
        { L"Ctrl+C",         L"Copy the selected row to the clipboard" },
        { L"Ctrl+E",         L"Export CSV / JSON" },
        { L"Ctrl+S",         L"Settings (AI key, notifications, refresh interval)" },
        { L"Ctrl+D",         L"Toggle demo mode (sample data)" },
        { L"5",              L"Network graph tab" },
        { L"Right-click",        L"Block IP, VirusTotal, SHA-256, open file location, terminate" },
        { L"Intelligence",     L"AbuseIPDB · DNS blacklists · CIRCL passive DNS · RDAP ownership · VirusTotal · TLS certificate · HTTP banner · hosts redirect · inbound port scan" },
    };
    int y = card.top + S(72);
    const int lh = S(24);
    for (const auto& r : rows) {
        RECT kr = { card.left + S(24), y, card.left + S(190), y + lh };
        p.FillRoundRect(RECT{ kr.left - S(4), y + S(2), kr.left + S(150), y + lh - S(2) }, S(4), clr::SurfaceHi);
        p.Text(r.key, RECT{ kr.left + S(6), y, kr.left + S(150), y + lh }, m_fSmallBold, clr::Cyan,
               DT_LEFT | DT_VCENTER | DT_SINGLELINE);
        RECT vr = { card.left + S(190), y, card.right - S(20), y + lh };
        p.Text(Tr(r.what), vr, m_fUi, clr::TextDim, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
        y += lh;
    }

    RECT q = { card.left + S(24), y + S(8), card.right - S(20), card.bottom - S(10) };
    p.Text(std::wstring(Tr(L"Search syntax:  proc:chrome  ip:142.250  port:443  country:US  org:cloudflare  risk:>50  threat:>50  module:ntdll  cert:google  user:SYSTEM  host:akamai   (can be combined)")) + L"\n" +
           Tr(L"Data sources: DNS cache domain matching, hosts redirect detection, RDAP network ownership, VirusTotal community scores, HTTP banner + end-of-life software check, inbound SYN port-scan detection, LAN device discovery, Wi-Fi connection details, scheduled task and service binary persistence scan."),
           q, m_fSmall, clr::TextFaint, DT_LEFT | DT_TOP | DT_WORDBREAK);
}

void App::DrawStatus(Painter& p) {
    p.FillRect(m_rcStatus, clr::Surface);
    p.Line(m_rcStatus.left, m_rcStatus.top, m_rcStatus.right, m_rcStatus.top, clr::Border);

    int danger = 0, warn = 0, pub = 0;
    for (const auto& c : m_rows) {
        if (c.risk == Risk::Danger) danger++;
        else if (c.risk == Risk::Warn) warn++;
        if (c.isRemotePublic) pub++;
    }
    unsigned long long upSec = (NowMs() - m_startedAt) / 1000;

    wchar_t buf[640];
    RECT r = { m_rcStatus.left + S(12), m_rcStatus.top, m_rcStatus.right - S(330), m_rcStatus.bottom };

    if (m_lastRefreshTs) {
        RECT tr = { m_rcStatus.right - S(540), m_rcStatus.top, m_rcStatus.right - S(400), m_rcStatus.bottom };
        const unsigned long long lag = NowMs() - m_lastRefreshTs;
        const unsigned long long limit = (unsigned long long)m_interval * 3 + 1500;
        std::wstring stamp = L"⟳ " + ClockText(m_lastRefreshTs / 1000, 0);
        COLORREF col = m_paused ? clr::Yellow : clr::TextFaint;
        if (!m_paused && lag > limit) {
            stamp += L" (+" + std::to_wstring(lag / 1000) + L"s)";
            col = clr::Red;
        }
        p.Text(stamp, tr, m_fSmall, col, DT_RIGHT | DT_VCENTER | DT_SINGLELINE);
    }

    if (!m_toast.empty() && NowMs() < m_toastUntil) {
        p.Text(L"● " + m_toast, r, m_fSmallBold, m_toastColor,
               DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
    } else {
        swprintf(buf, 640,
                 Tr(L"%d sockets  •  %d internet  •  %d apps  •  CPU %.0f%%  •  %d critical / %d suspicious  •  history: %d records (%d closed)  •  shown: %d  •  uptime: %llu:%02llu  •  %s"),
                 (int)m_rows.size(), pub, (int)m_apps.size(), m_mon.Procs().TotalCpu(), danger, warn,
                 (int)m_hist.Entries().size(), (int)m_hist.ClosedCount(), TotalRows(),
                 upSec / 60, upSec % 60, m_paused ? Tr(L"PAUSED") : Tr(L"live"));
        if (m_demo) {
            wchar_t db[700];
            swprintf(db, 700, Tr(L"%s  •  DEMO MODE (sample data)"), buf);
            p.Text(db, r, m_fSmall, m_demo ? clr::Cyan : clr::TextDim,
                   DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
        } else {
            p.Text(buf, r, m_fSmall, clr::TextDim, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
        }
    }

    std::wstring right;
    if (!m_isAdmin) right = Tr(L"⚠ run as administrator for per-connection rates (click)  ·  ");
    else if (!m_mon.EstatsAvailable()) right = Tr(L"connection rate counters warming up…  ·  ");
    right += m_geoOnline ? Tr(L"IP geolocation: on") : Tr(L"IP geolocation: off");
    right += Tr(L"  ·  cache: ") + std::to_wstring((int)m_geo.CacheCount());
    if (m_geoOnline) {
        const size_t gp = m_geo.PendingCount();
        if (gp) right += L" (" + std::to_wstring((int)gp) + Tr(L" pending)");
    }
    if (m_threatOnline) {
        right += Tr(L"  ·  threat: ");
        if (m_abuseKey.empty()) right += Tr(L"blacklists");
        else right += Tr(L"AbuseIPDB + blacklists");
        size_t pend = m_threat.PendingCount();
        if (pend) right += L" (" + std::to_wstring((int)pend) + Tr(L" pending)") + L"";
    }
    if (m_effInterval > m_interval) {
        wchar_t sb[160];
        swprintf(sb, 160, Tr(L"  ·  refresh auto-slowed to %.1f s (collection takes %u ms)"),
                 m_effInterval / 1000.0, m_lastTickCostMs);
        right += sb;
    }
    if (m_rdapOnline) right += Tr(L"  ·  RDAP");
    if (m_vtOnline)   right += Tr(L"  ·  VirusTotal");
    if (m_bannerOnline) {
        size_t bp = m_banner.PendingCount();
        if (bp) right += Tr(L"  ·  banner (") + std::to_wstring((int)bp) + L")";
    }

    RECT rr = { m_rcStatus.right - S(430), m_rcStatus.top, m_rcStatus.right - S(12), m_rcStatus.bottom };
    p.Text(right, rr, m_fSmall, m_isAdmin ? clr::TextFaint : clr::Yellow,
           DT_RIGHT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
}

void App::OnPaint() {
    PAINTSTRUCT ps;
    HDC hdc = BeginPaint(m_hwnd, &ps);
    RECT rc;
    GetClientRect(m_hwnd, &rc);

    HDC mem = CreateCompatibleDC(hdc);
    HBITMAP bmp = CreateCompatibleBitmap(hdc, (std::max)(1L, rc.right), (std::max)(1L, rc.bottom));
    HGDIOBJ oldBmp = SelectObject(mem, bmp);

    {
        Painter p(mem);
        p.FillRect(rc, clr::Bg);
        m_buttons.erase(std::remove_if(m_buttons.begin(), m_buttons.end(),
                        [](const Button& b) {
                            return b.id == ID_TAB_CONNS || b.id == ID_TAB_APPS ||
                                   b.id == ID_TAB_HIST  || b.id == ID_TAB_STATS ||
                                   b.id == ID_TAB_GRAPH;
                        }), m_buttons.end());
        DrawHeader(p);
        DrawToolbar(p);
        if (m_tab == Tab::Graph) DrawGraph(p);
        else if (IsTableTab()) { DrawTable(p); DrawDetail(p); }
        else                   DrawStats(p);
        DrawStatus(p);
        if (m_overlay != Overlay::None) DrawOverlay(p);
        if (m_showHelp) DrawHelp(p);
    }

    BitBlt(hdc, 0, 0, rc.right, rc.bottom, mem, 0, 0, SRCCOPY);
    SelectObject(mem, oldBmp);
    DeleteObject(bmp);
    DeleteDC(mem);
    EndPaint(m_hwnd, &ps);
}

int App::MaxScroll() const {
    int contentH = TotalRows() * RowH();
    int viewH = m_rcRows.bottom - m_rcRows.top;
    return (std::max)(0, contentH - viewH);
}

int App::RowAt(int y) const {
    if (!IsTableTab()) return -1;
    if (y < m_rcRows.top || y >= m_rcRows.bottom) return -1;
    int idx = (y - m_rcRows.top + m_scrollY) / RowH();
    if (idx < 0 || idx >= TotalRows()) return -1;
    return idx;
}

void App::SetSelection(int viewIndex) {
    m_selRow = viewIndex;
    if (viewIndex >= 0 && viewIndex < (int)m_view.size()) {
        if (m_tab == Tab::Conns) {
            m_selKey = m_rows[m_view[viewIndex]].Key();
            m_selPid = m_rows[m_view[viewIndex]].pid;
        } else if (m_tab == Tab::Apps) {
            m_selPid = m_apps[m_view[viewIndex]].pid;
            m_selKey.clear();
        } else if (m_tab == Tab::History) {
            const auto& ents = m_hist.Entries();
            m_selKey = ents[m_view[viewIndex]].key;
            m_selPid = ents[m_view[viewIndex]].pid;
        }
    }

    if (m_selPid) m_mon.Procs().RequestHash(m_selPid);
    m_aiScroll = 0;
}

void App::EnsureVisible() {
    if (m_selRow < 0) return;
    const int rowH = RowH();
    int top = m_selRow * rowH;
    int viewH = m_rcRows.bottom - m_rcRows.top;
    if (top < m_scrollY) m_scrollY = top;
    else if (top + rowH > m_scrollY + viewH) m_scrollY = top + rowH - viewH;
    m_scrollY = (std::max)(0, (std::min)(m_scrollY, MaxScroll()));
}

void App::SetSearch(const std::wstring& text) {
    m_searchText = text;
    m_query = ParseQuery(text);
    if (m_search) SetWindowTextW(m_search, text.c_str());
    m_scrollY = 0;
    RebuildView();
    InvalidateRect(m_hwnd, nullptr, FALSE);
}

void App::OnLButtonDown(int x, int y) {
    SetFocus(m_hwnd);

    if (m_overlay != Overlay::None) {
        POINT pt{ x, y };
        if (PtInRect(&m_ovBtn1, pt)) {
            if (m_overlay == Overlay::Welcome) {
                m_overlay = Overlay::None;
                WritePrivateProfileStringW(L"ui", L"welcome", L"0",
                                           ConfigPath().c_str());
                InvalidateRect(m_hwnd, nullptr, FALSE);
            } else {
                m_overlay = Overlay::None;
                InvalidateRect(m_hwnd, nullptr, FALSE);
            }
        } else if (PtInRect(&m_ovBtn2, pt) && m_overlay == Overlay::Welcome) {
            m_overlay = Overlay::None;
            WritePrivateProfileStringW(L"ui", L"welcome", L"0",
                                       ConfigPath().c_str());
            EnterDemo();
        } else if (PtInRect(&m_ovBtn3, pt) && m_overlay == Overlay::Welcome) {
            ShowOverlay(Overlay::Privacy);
        }
        return;
    }

    if (m_demo && PtInRect(&m_rcDemoExit, POINT{ x, y })) {
        ExitDemo();
        return;
    }

    if (PtInRect(&m_aiBtn1, POINT{ x, y })) { FollowUpAi(0); return; }
    if (PtInRect(&m_aiBtn2, POINT{ x, y })) { FollowUpAi(1); return; }
    if (PtInRect(&m_aiBtn3, POINT{ x, y })) { FollowUpAi(2); return; }

    if (!m_isAdmin && PtInRect(&m_rcStatus, POINT{ x, y }) && x > m_rcStatus.right - S(390)) {
        ScopedTimerPause pause(m_hwnd, 1, m_interval);
        if (DialogBoxParamW(m_inst, MAKEINTRESOURCEW(IDD_ELEVATE), m_hwnd,
                           &App::ElevateProc, (LPARAM)this) == IDYES) {
            SavePrefs();
            Relaunch(true);
            DestroyWindow(m_hwnd);
        }
        return;
    }

    for (const auto& b : m_buttons)
        if (PtInRect(&b.rc, POINT{ x, y })) { OnCommand(b.id); return; }

    if (!IsTableTab()) return;

    if (PtInRect(&m_rcScroll, POINT{ x, y }) && MaxScroll() > 0) {
        int viewH = m_rcRows.bottom - m_rcRows.top;
        int contentH = TotalRows() * RowH();
        int thumbH = (std::max)(S(30), MulDiv(viewH, viewH, contentH));
        int ty = m_rcScroll.top + MulDiv(m_scrollY, viewH - thumbH, MaxScroll());
        if (y >= ty && y <= ty + thumbH) {
            m_dragScroll = true;
            m_dragOffset = y - ty;
            SetCapture(m_hwnd);
        } else {
            int rel = y - m_rcScroll.top - thumbH / 2;
            m_scrollY = MulDiv(rel, MaxScroll(), (std::max)(1, viewH - thumbH));
            m_scrollY = (std::max)(0, (std::min)(m_scrollY, MaxScroll()));
        }
        InvalidateRect(m_hwnd, nullptr, FALSE);
        return;
    }

    if (PtInRect(&m_rcTableHead, POINT{ x, y })) {
        for (size_t k = 0; k < m_visCols.size(); ++k) {
            if (x >= m_colX[k] && x < m_colX[k] + m_colW[k]) {
                int id = Cols()[m_visCols[k]].id;
                int& sc = SortCol();
                int& sd = SortDir();
                if (sc == id) sd = -sd;
                else { sc = id; sd = -1; }
                RebuildView();
                InvalidateRect(m_hwnd, nullptr, FALSE);
                return;
            }
        }
        return;
    }

    int row = RowAt(y);
    if (row >= 0) {
        SetSelection(row);
        std::lock_guard<std::mutex> lk(m_aiMtx);
        m_aiText.clear();
        m_aiTitle.clear();
    }
    InvalidateRect(m_hwnd, nullptr, FALSE);
}

void App::OnLButtonUp(int, int) {
    if (m_dragScroll) {
        m_dragScroll = false;
        ReleaseCapture();
        InvalidateRect(m_hwnd, nullptr, FALSE);
    }
}

void App::OnMouseMove(int x, int y) {
    if (m_dragScroll) {
        int viewH = m_rcRows.bottom - m_rcRows.top;
        int contentH = TotalRows() * RowH();
        int thumbH = (std::max)(S(30), MulDiv(viewH, viewH, (std::max)(1, contentH)));
        int rel = y - m_dragOffset - m_rcScroll.top;
        m_scrollY = MulDiv(rel, MaxScroll(), (std::max)(1, viewH - thumbH));
        m_scrollY = (std::max)(0, (std::min)(m_scrollY, MaxScroll()));
        InvalidateRect(m_hwnd, nullptr, FALSE);
        return;
    }

    int oldHotBtn = m_hotBtn, oldHover = m_hoverRow, oldHotCol = m_hotCol;
    m_hotBtn = -1;
    for (const auto& b : m_buttons)
        if (PtInRect(&b.rc, POINT{ x, y })) { m_hotBtn = b.id; break; }

    m_hoverRow = RowAt(y);

    m_hotCol = -1;
    if (IsTableTab() && PtInRect(&m_rcTableHead, POINT{ x, y })) {
        for (size_t k = 0; k < m_visCols.size(); ++k)
            if (x >= m_colX[k] && x < m_colX[k] + m_colW[k]) { m_hotCol = (int)k; break; }
    }

    if (oldHotBtn != m_hotBtn || oldHover != m_hoverRow || oldHotCol != m_hotCol)
        InvalidateRect(m_hwnd, nullptr, FALSE);

    TRACKMOUSEEVENT tme;
    tme.cbSize = sizeof(tme);
    tme.dwFlags = TME_LEAVE;
    tme.hwndTrack = m_hwnd;
    tme.dwHoverTime = 0;
    TrackMouseEvent(&tme);
}

void App::OnMouseWheel(int delta, POINT pt) {
    ScreenToClient(m_hwnd, &pt);
    if (m_showDetail && IsTableTab() && PtInRect(&m_rcDetail, pt)) {
        m_aiScroll -= (delta / WHEEL_DELTA) * S(28);
        m_aiScroll = (std::max)(0, (std::min)(m_aiScroll, m_aiMaxScroll));
    } else if (IsTableTab()) {
        m_scrollY -= (delta / WHEEL_DELTA) * RowH() * 3;
        m_scrollY = (std::max)(0, (std::min)(m_scrollY, MaxScroll()));
    }
    InvalidateRect(m_hwnd, nullptr, FALSE);
}

void App::OnKeyDown(WPARAM key) {
    const bool ctrl = (GetKeyState(VK_CONTROL) & 0x8000) != 0;
    switch (key) {
        case VK_DOWN:  if (m_selRow + 1 < TotalRows()) { SetSelection(m_selRow + 1); EnsureVisible(); } break;
        case VK_UP:    if (m_selRow > 0) { SetSelection(m_selRow - 1); EnsureVisible(); } break;
        case VK_NEXT:  SetSelection((std::min)(TotalRows() - 1, (m_selRow < 0 ? 0 : m_selRow) + 12)); EnsureVisible(); break;
        case VK_PRIOR: SetSelection((std::max)(0, (m_selRow < 0 ? 0 : m_selRow) - 12)); EnsureVisible(); break;
        case VK_HOME:  if (TotalRows()) { SetSelection(0); EnsureVisible(); } break;
        case VK_END:   if (TotalRows()) { SetSelection(TotalRows() - 1); EnsureVisible(); } break;
        case VK_SPACE: OnCommand(ID_BTN_PAUSE); return;
        case VK_F5:    Tick(true); break;
        case VK_F1:    m_showHelp = !m_showHelp; break;
        case VK_RETURN:RunAiAnalysis(ctrl); return;
        case VK_DELETE: KillSelectedProcess((GetKeyState(VK_SHIFT) & 0x8000) != 0); return;
        case VK_TAB: {
            Tab next = (m_tab == Tab::Conns) ? Tab::Apps
                     : (m_tab == Tab::Apps)  ? Tab::History
                     : (m_tab == Tab::History) ? Tab::Stats
                     : (m_tab == Tab::Stats) ? Tab::Graph : Tab::Conns;
            OnCommand(next == Tab::Conns ? ID_TAB_CONNS : next == Tab::Apps ? ID_TAB_APPS
                      : next == Tab::History ? ID_TAB_HIST
                      : next == Tab::Stats ? ID_TAB_STATS : ID_TAB_GRAPH);
            return;
        }
        case VK_ESCAPE:
            if (m_overlay == Overlay::Welcome) {
                m_overlay = Overlay::None;
                WritePrivateProfileStringW(L"ui", L"welcome", L"0",
                                           ConfigPath().c_str());
                InvalidateRect(m_hwnd, nullptr, FALSE);
                break;
            }
            if (m_overlay == Overlay::Privacy) { m_overlay = Overlay::None; InvalidateRect(m_hwnd, nullptr, FALSE); break; }
            if (m_showHelp) { m_showHelp = false; break; }
            if (!m_searchText.empty()) SetSearch(L""); break;
        case '1': OnCommand(ID_TAB_CONNS); return;
        case '2': OnCommand(ID_TAB_APPS);  return;
        case '3': OnCommand(ID_TAB_HIST);  return;
        case '4': OnCommand(ID_TAB_STATS); return;
        case '5': OnCommand(ID_TAB_GRAPH); return;
        case 'F': if (ctrl) { SetFocus(m_search); return; } break;
        case 'D': if (ctrl) { m_demo ? ExitDemo() : EnterDemo(); return; } break;
        case 'C': if (ctrl) { OnCommand(IDM_COPY_ROW); return; } break;
        case 'E': if (ctrl) { ExportData(); return; } break;
        case 'S': if (ctrl) { ShowSettings(); return; } break;
        case 'P': if (ctrl) { SuspendSelectedProcess(); return; } break;
        case 'K': if (ctrl) { KillSelectedProcess(true); return; } break;
    }
    InvalidateRect(m_hwnd, nullptr, FALSE);
}

void App::OnCommand(int id) {
    switch (id) {
        case ID_FILTER_ALL:      m_filter = Filter::All;        break;
        case ID_FILTER_ACTIVE:   m_filter = Filter::Active;     break;
        case ID_FILTER_LISTEN:   m_filter = Filter::Listening;  break;
        case ID_FILTER_SUSPECT:  m_filter = Filter::Suspicious; break;
        case ID_FILTER_TCP:      m_filter = Filter::Tcp;        break;
        case ID_FILTER_UDP:      m_filter = Filter::Udp;        break;
        case ID_FILTER_EXTERNAL: m_filter = Filter::External;   break;
        case ID_FILTER_UNSIGNED: m_filter = Filter::Unsigned_;  break;
        case ID_FILTER_HTTPS:    m_filter = Filter::Https;       break;
        case ID_FILTER_UNKNOWN:  m_filter = Filter::UnknownProc; break;
        case ID_FILTER_RECENT:   m_filter = Filter::Recent;      break;
        case ID_TAB_CONNS:       m_tab = Tab::Conns;   m_scrollY = 0; m_selRow = -1; break;
        case ID_TAB_APPS:        m_tab = Tab::Apps;    m_scrollY = 0; m_selRow = -1; break;
        case ID_TAB_HIST:        m_tab = Tab::History; m_scrollY = 0; m_selRow = -1; break;
        case ID_TAB_GRAPH:       m_tab = Tab::Graph;   m_scrollY = 0; m_selRow = -1; break;
        case ID_TAB_STATS:       m_tab = Tab::Stats;   m_scrollY = 0; m_selRow = -1; break;
        case ID_BTN_PAUSE:       m_paused = !m_paused; break;
        case ID_BTN_REFRESH:     Tick(true); break;
        case ID_BTN_DETAIL:      m_showDetail = !m_showDetail; break;
        case ID_BTN_EXPORT:      ExportData(); break;
        case ID_BTN_SETTINGS:    ShowSettings(); break;
        case ID_BTN_AI:          RunAiAnalysis(false); break;
        case IDM_AI_BULK:        RunAiAnalysis(true); break;
        case IDM_COPY_IP: {
            if (const Conn* c = SelectedConn())      CopyToClipboard(c->remoteIp);
            else if (const HistEntry* h = SelectedHist()) CopyToClipboard(h->remoteIp);
            break;
        }
        case IDM_COPY_PATH: {
            if (const Conn* c = SelectedConn())        CopyToClipboard(c->procPath);
            else if (const AppRow* a = SelectedApp())  CopyToClipboard(a->path);
            else if (const HistEntry* h = SelectedHist()) CopyToClipboard(h->path);
            break;
        }
        case IDM_COPY_CMD: {
            DWORD pid = 0;
            if (const Conn* c = SelectedConn())       pid = c->pid;
            else if (const AppRow* a = SelectedApp()) pid = a->pid;
            if (pid) CopyToClipboard(m_mon.Procs().Get(pid).cmdline);
            break;
        }
        case IDM_FILTER_PROC: {
            std::wstring n;
            if (const Conn* c = SelectedConn())       n = c->procName;
            else if (const AppRow* a = SelectedApp()) n = a->name;
            else if (const HistEntry* h = SelectedHist()) n = h->proc;
            if (!n.empty()) SetSearch(L"proc:" + n);
            return;
        }
        case IDM_FILTER_IP: {
            std::wstring ip;
            if (const Conn* c = SelectedConn())            ip = c->remoteIp;
            else if (const HistEntry* h = SelectedHist())  ip = h->remoteIp;
            if (!ip.empty()) SetSearch(L"ip:" + ip);
            return;
        }
        case IDM_COPY_ROW: {
            if (const Conn* c = SelectedConn()) {
                CopyToClipboard(c->procName + L"\t" + std::to_wstring(c->pid) + L"\t" + c->publisher +
                                L"\t" + c->ProtoText() + L"\t" + c->LocalText() + L"\t" + c->RemoteText() +
                                L"\t" + c->StateText() + L"\t" + c->country + L"\t" + c->city + L"\t" +
                                c->org + L"\t" + c->asn + L"\t" + c->host + L"\t" +
                                std::to_wstring(c->riskScore) + L"\t" + c->riskReason);
            } else if (const AppRow* a = SelectedApp()) {
                CopyToClipboard(a->name + L"\t" + std::to_wstring(a->pid) + L"\t" + a->publisher +
                                L"\t" + a->user + L"\t" + a->path);
            } else if (const HistEntry* h = SelectedHist()) {
                CopyToClipboard(h->TimeText() + L"\t" + h->proc + L"\t" + h->remoteIp + L":" +
                                std::to_wstring(h->remotePort) + L"\t" + h->country + L"\t" + h->org);
            }
            break;
        }
        case IDM_OPEN_FOLDER: {
            std::wstring path;
            if (const Conn* c = SelectedConn())            path = c->procPath;
            else if (const AppRow* a = SelectedApp())      path = a->path;
            else if (const HistEntry* h = SelectedHist())  path = h->path;
            if (!path.empty()) {
                std::wstring arg = L"/select,\"" + path + L"\"";
                ShellExecuteW(m_hwnd, L"open", L"explorer.exe", arg.c_str(), nullptr, SW_SHOWNORMAL);
            }
            break;
        }
        case ID_BTN_BLOCK: {
            std::wstring ip;
            if (const Conn* c = SelectedConn())           { if (c->isRemotePublic) ip = c->remoteIp; }
            else if (const HistEntry* h = SelectedHist()) ip = h->remoteIp;
            if (ip.empty()) break;
            if (m_blockedIps.count(ip)) UnblockSelectedIp();
            else                        BlockSelectedIp();
            break;
        }
        case ID_BTN_KILL:
        case IDM_KILL:      KillSelectedProcess(false); break;
        case IDM_KILL_TREE: KillSelectedProcess(true);  break;
        case IDM_SUSPEND:   SuspendSelectedProcess();   break;
        case IDM_PROPERTIES:ShowProcessProperties();    break;
        case IDM_COPY_HASH: {
            DWORD pid = SelectedPid();
            if (!pid) break;
            ProcDetails d = m_mon.Procs().Get(pid);
            if (d.sha256.empty() || d.sha256 == L"…") {
                m_mon.Procs().RequestHash(pid);
                Toast(Tr(L"Computing SHA-256, it will appear in the details panel…"), clr::Cyan);
            } else {
                CopyToClipboard(d.sha256);
                Toast(Tr(L"SHA-256 copied to clipboard."), clr::Green);
            }
            break;
        }
        case IDM_VT_FILE: {
            DWORD pid = SelectedPid();
            if (!pid) break;
            ProcDetails d = m_mon.Procs().Get(pid);
            if (d.sha256.size() == 64) {
                std::wstring url = L"https://www.virustotal.com/gui/file/" + d.sha256;
                ShellExecuteW(m_hwnd, L"open", url.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
            } else {
                m_mon.Procs().RequestHash(pid);
                Toast(Tr(L"The file hash must be computed first — try again in a few seconds."), clr::Yellow);
            }
            break;
        }
        case IDM_BLOCK_IP: BlockSelectedIp(); break;
        case IDM_UNBLOCK_IP: UnblockSelectedIp(); break;
        case IDM_AI:       RunAiAnalysis(false); break;
        case IDM_WHOIS: {
            std::wstring ip;
            if (const Conn* c = SelectedConn())            ip = c->remoteIp;
            else if (const HistEntry* h = SelectedHist())  ip = h->remoteIp;
            if (!ip.empty()) {
                std::wstring url = L"https://www.virustotal.com/gui/ip-address/" + ip;
                ShellExecuteW(m_hwnd, L"open", url.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
            }
            break;
        }
        case IDM_ABUSE_OPEN: {
            std::wstring ip;
            if (const Conn* c = SelectedConn())            ip = c->remoteIp;
            else if (const HistEntry* h = SelectedHist())  ip = h->remoteIp;
            if (!ip.empty()) {
                std::wstring url = L"https://www.abuseipdb.com/check/" + ip;
                ShellExecuteW(m_hwnd, L"open", url.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
            }
            break;
        }
        case IDM_CIRCL_OPEN: {
            std::wstring ip;
            if (const Conn* c = SelectedConn())            ip = c->remoteIp;
            else if (const HistEntry* h = SelectedHist())  ip = h->remoteIp;
            if (!ip.empty()) {
                std::wstring url = L"https://cve.circl.lu/pdns/query/" + ip;
                ShellExecuteW(m_hwnd, L"open", url.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
            }
            break;
        }
        case IDM_THREAT_REFRESH: {
            std::wstring ip;
            if (const Conn* c = SelectedConn())            ip = c->remoteIp;
            else if (const HistEntry* h = SelectedHist())  ip = h->remoteIp;
            if (!ip.empty()) {
                m_threat.Invalidate(ip);
                Toast(Tr(L"Re-querying threat intelligence: ") + ip, clr::Cyan);
            }
            break;
        }
        case IDM_CERT_REFRESH: {
            if (const Conn* c = SelectedConn()) {
                if (!c->isRemotePublic) {
                    Toast(Tr(L"This connection has no remote certificate."), clr::Yellow);
                    break;
                }
                std::wstring key = c->remoteIp + L":" + std::to_wstring(c->remotePort);
                m_cert.Invalidate(key);
                m_banner.Invalidate(key);
                Toast(Tr(L"Re-fetching TLS certificate and banner: ") + c->RemoteText(), clr::Cyan);
            }
            break;
        }
        case IDM_TRAY_SHOW:
            ShowWindow(m_hwnd, SW_SHOW);
            ShowWindow(m_hwnd, SW_RESTORE);
            SetForegroundWindow(m_hwnd);
            return;
        case IDM_TRAY_PAUSE: m_paused = !m_paused; break;
        case IDM_TRAY_EXIT:  DestroyWindow(m_hwnd); return;
        default: return;
    }
    Layout();
    RebuildView();
    InvalidateRect(m_hwnd, nullptr, FALSE);
}

void App::OnContextMenu(int sx, int sy) {
    POINT pt{ sx, sy };
    POINT cl = pt;
    ScreenToClient(m_hwnd, &cl);
    int row = RowAt(cl.y);
    if (row >= 0) {
        SetSelection(row);
        InvalidateRect(m_hwnd, nullptr, FALSE);
    }
    if (m_selRow < 0) return;

    ScopedTimerPause pause(m_hwnd, 1, m_interval);
    HMENU menu = CreatePopupMenu();
    if (!menu) return;
    AppendMenuW(menu, MF_STRING, IDM_AI,          Tr(L"Analyze with AI\tEnter"));
    AppendMenuW(menu, MF_STRING, IDM_AI_BULK,     Tr(L"Batch-analyze riskiest connections\tCtrl+Enter"));
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, IDM_FILTER_PROC, Tr(L"Show only this app"));
    if (m_tab != Tab::Apps)
        AppendMenuW(menu, MF_STRING, IDM_FILTER_IP, Tr(L"Show only this IP"));
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    if (m_tab != Tab::Apps) {
        AppendMenuW(menu, MF_STRING, IDM_COPY_IP,  Tr(L"Copy destination IP"));
        AppendMenuW(menu, MF_STRING, IDM_WHOIS,    Tr(L"Open in VirusTotal"));
        AppendMenuW(menu, MF_STRING, IDM_ABUSE_OPEN, Tr(L"Check on AbuseIPDB"));
        AppendMenuW(menu, MF_STRING, IDM_CIRCL_OPEN, Tr(L"Open passive DNS records for IP (CIRCL)"));
        {
            std::wstring selIp;
            if (const Conn* sc = SelectedConn())           selIp = sc->remoteIp;
            else if (const HistEntry* sh = SelectedHist()) selIp = sh->remoteIp;
            if (!selIp.empty() && m_blockedIps.count(selIp))
                AppendMenuW(menu, MF_STRING, IDM_UNBLOCK_IP, Tr(L"Remove firewall block for this IP"));
            else
                AppendMenuW(menu, MF_STRING, IDM_BLOCK_IP, Tr(L"Block in Windows Firewall"));
        }
        AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(menu, MF_STRING, IDM_THREAT_REFRESH, Tr(L"Re-query threat intelligence"));
        AppendMenuW(menu, MF_STRING, IDM_CERT_REFRESH,   Tr(L"Re-fetch TLS certificate"));
        AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    }
    AppendMenuW(menu, MF_STRING, IDM_COPY_ROW,    Tr(L"Copy row\tCtrl+C"));
    AppendMenuW(menu, MF_STRING, IDM_COPY_PATH,   Tr(L"Copy file path"));
    AppendMenuW(menu, MF_STRING, IDM_COPY_CMD,    Tr(L"Copy command line"));
    AppendMenuW(menu, MF_STRING, IDM_COPY_HASH,   Tr(L"Copy file SHA-256"));
    AppendMenuW(menu, MF_STRING, IDM_VT_FILE,     Tr(L"Check file hash (SHA-256) on VirusTotal"));
    AppendMenuW(menu, MF_STRING, IDM_OPEN_FOLDER, Tr(L"Open file location"));
    AppendMenuW(menu, MF_STRING, IDM_PROPERTIES,  Tr(L"File properties…"));
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    {
        DWORD spid = SelectedPid();
        ProcRuntime srt = spid ? m_mon.Procs().Runtime(spid) : ProcRuntime{};
        AppendMenuW(menu, MF_STRING, IDM_SUSPEND,
                    srt.suspended ? Tr(L"Resume process\tCtrl+P") : Tr(L"Suspend process\tCtrl+P"));
    }
    AppendMenuW(menu, MF_STRING, IDM_KILL,        Tr(L"Force-kill process\tDel"));
    AppendMenuW(menu, MF_STRING, IDM_KILL_TREE,   Tr(L"Kill process tree (with children)\tShift+Del"));

    int cmd = (int)TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, pt.x, pt.y, 0, m_hwnd, nullptr);
    DestroyMenu(menu);
    if (cmd) OnCommand(cmd);
}

void App::OnTray(LPARAM lp) {
    if (lp == WM_LBUTTONDBLCLK || lp == WM_LBUTTONUP) {
        OnCommand(IDM_TRAY_SHOW);
        return;
    }
    if (lp == WM_RBUTTONUP) {
        POINT pt;
        GetCursorPos(&pt);
        HMENU m = CreatePopupMenu();
        if (!m) return;
        AppendMenuW(m, MF_STRING, IDM_TRAY_SHOW,  Tr(L"Show NetLurker"));
        AppendMenuW(m, MF_STRING, IDM_TRAY_PAUSE, m_paused ? Tr(L"Resume monitoring") : Tr(L"Pause monitoring"));
        AppendMenuW(m, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(m, MF_STRING, IDM_TRAY_EXIT,  Tr(L"Exit"));
        SetForegroundWindow(m_hwnd);
        int cmd = (int)TrackPopupMenu(m, TPM_RETURNCMD | TPM_RIGHTBUTTON, pt.x, pt.y, 0, m_hwnd, nullptr);
        DestroyMenu(m);
        if (cmd) OnCommand(cmd);
    }
}

void App::CopyToClipboard(const std::wstring& text) {
    if (!OpenClipboard(m_hwnd)) return;
    EmptyClipboard();
    size_t bytes = (text.size() + 1) * sizeof(wchar_t);
    HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (h) {
        void* p = GlobalLock(h);
        if (p) {
            memcpy(p, text.c_str(), bytes);
            GlobalUnlock(h);
            SetClipboardData(CF_UNICODETEXT, h);
        } else GlobalFree(h);
    }
    CloseClipboard();
}

DWORD App::SelectedPid(std::wstring* nameOut) const {
    DWORD pid = 0;
    std::wstring name;
    if (const Conn* c = SelectedConn())            { pid = c->pid; name = c->procName; }
    else if (const AppRow* a = SelectedApp())      { pid = a->pid; name = a->name; }
    else if (const HistEntry* h = SelectedHist())  { pid = h->pid; name = h->proc; }
    if (nameOut) *nameOut = name;
    return pid;
}

void App::Toast(const std::wstring& msg, COLORREF color) {
    m_toast      = msg;
    m_toastColor = color;
    m_toastUntil = NowMs() + 6000;
    InvalidateRect(m_hwnd, &m_rcStatus, FALSE);
}

void App::KillSelectedProcess(bool tree) {
    std::wstring name;
    DWORD pid = SelectedPid(&name);
    if (!pid) { Toast(Tr(L"Select a row first."), clr::Yellow); return; }
    if (pid <= 4) { Toast(Tr(L"System processes cannot be terminated."), clr::Orange); return; }
    if (pid == GetCurrentProcessId()) { Toast(Tr(L"NetLurker cannot terminate itself."), clr::Orange); return; }

    if (m_confirmKill) {
        ScopedTimerPause pause(m_hwnd, 1, m_interval);
        std::wstring msg = L"\"" + name + L"\" (PID " + std::to_wstring(pid) + L") " +
                           (tree ? Tr(L"and all of its child processes ") : L"") +
                           Tr(L"will be force-terminated. Continue?\n\nUnsaved data will be lost.");
        if (MessageBoxW(m_hwnd, msg.c_str(), Tr(L"NetLurker — Terminate process"),
                        MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2) != IDYES) return;
    }

    KillResult r = tree ? KillProcessTree(pid, true) : KillProcess(pid, true);
    if (r.ok) {
        std::wstring t = name + Tr(L" terminated");
        if (tree && r.killed > 1) t += L" (" + std::to_wstring(r.killed) + Tr(L" processes)");
        if (!r.message.empty())   t += L" — " + r.message;
        Toast(t, clr::Green);
        m_mon.Procs().Invalidate(pid);
    } else {
        Toast(name + Tr(L" could not be terminated: ") +
              (r.message.empty() ? std::wstring(Tr(L"unknown error")) : r.message), clr::Red);
    }
    Tick(true);
    InvalidateRect(m_hwnd, nullptr, FALSE);
}

void App::SuspendSelectedProcess() {
    std::wstring name;
    DWORD pid = SelectedPid(&name);
    if (!pid || pid <= 4) { Toast(Tr(L"This process cannot be suspended."), clr::Orange); return; }
    if (pid == GetCurrentProcessId()) { Toast(Tr(L"NetLurker cannot suspend itself."), clr::Orange); return; }

    ProcRuntime rt = m_mon.Procs().Runtime(pid);
    const bool wantSuspend = !rt.suspended;
    if (SuspendProcess(pid, wantSuspend)) {
        Toast(name + (wantSuspend ? Tr(L" suspended") : Tr(L" resumed")),
              wantSuspend ? clr::Yellow : clr::Green);
    } else {
        Toast(name + Tr(L" could not be suspended (administrator rights may be required)."), clr::Red);
    }
    Tick(true);
    InvalidateRect(m_hwnd, nullptr, FALSE);
}

void App::ShowProcessProperties() {
    std::wstring path;
    if (const Conn* c = SelectedConn())            path = c->procPath;
    else if (const AppRow* a = SelectedApp())      path = a->path;
    else if (const HistEntry* h = SelectedHist())  path = h->path;
    if (path.empty()) { Toast(Tr(L"File path unknown."), clr::Yellow); return; }
    SHELLEXECUTEINFOW sei;
    ZeroMemory(&sei, sizeof(sei));
    sei.cbSize = sizeof(sei);
    sei.fMask  = SEE_MASK_INVOKEIDLIST | SEE_MASK_FLAG_NO_UI;
    sei.lpVerb = L"properties";
    sei.lpFile = path.c_str();
    sei.nShow  = SW_SHOW;
    ShellExecuteExW(&sei);
}

void App::BlockSelectedIp() {
    std::wstring ip;
    if (const Conn* c = SelectedConn())           { if (c->isRemotePublic) ip = c->remoteIp; }
    else if (const HistEntry* h = SelectedHist()) { ip = h->remoteIp; }
    if (ip.empty()) return;
    ScopedTimerPause pause(m_hwnd, 1, m_interval);

    std::wstring msg = ip + Tr(L" — block outbound traffic to this address in Windows Firewall?\n\nRule name: NetLurker Block ") + ip;
    if (MessageBoxW(m_hwnd, msg.c_str(), Tr(L"NetLurker — Block IP"),
                    MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2) != IDYES) return;

    std::wstring args = L"advfirewall firewall add rule name=\"" + FwRuleNameFor(ip) +
                        L"\" dir=out action=block remoteip=" + ip;
    SHELLEXECUTEINFOW sei;
    ZeroMemory(&sei, sizeof(sei));
    sei.cbSize = sizeof(sei);
    sei.lpVerb = L"runas";
    sei.lpFile = L"netsh.exe";
    sei.lpParameters = args.c_str();
    sei.nShow = SW_HIDE;
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    if (!ShellExecuteExW(&sei) || !sei.hProcess) {
        MessageBoxW(m_hwnd, Tr(L"The firewall rule was NOT created (the elevation prompt was declined or netsh could not start)."),
                    L"NetLurker", MB_ICONWARNING | MB_OK);
        return;
    }
    WaitForSingleObject(sei.hProcess, 15000);
    DWORD rc = 1;
    GetExitCodeProcess(sei.hProcess, &rc);
    CloseHandle(sei.hProcess);

    RefreshFirewallRules(true);
    const bool present = m_blockedIps.count(ip) != 0;
    if (present) {
        Toast(Tr(L"Firewall rule active: outbound traffic to ") + ip + Tr(L" is blocked"), clr::Green);
    } else if (rc == 0 && !m_fwChecked) {
        MessageBoxW(m_hwnd, Tr(L"netsh reported success, but the rule list could not be read back for verification."),
                    L"NetLurker", MB_ICONINFORMATION | MB_OK);
    } else {
        MessageBoxW(m_hwnd, Tr(L"The firewall rule was NOT created. Windows Firewall may be managed by policy or disabled."),
                    L"NetLurker", MB_ICONWARNING | MB_OK);
    }
}

struct JsonObj {
    std::wstring s;
    bool first = true;
    void key(const wchar_t* k) {
        if (!first) s += L",";
        first = false;
        s += L"\"";
        s += k;
        s += L"\":";
    }
    void str(const wchar_t* k, const std::wstring& v) {
        key(k);
        s += L"\"" + Widen(json::Escape(Narrow(v))) + L"\"";
    }
    template <class T>
    void num(const wchar_t* k, T v) { key(k); s += std::to_wstring(v); }
    void real(const wchar_t* k, double v) {
        key(k);
        wchar_t b[48];
        swprintf(b, 48, L"%.2f", v);
        s += b;
    }
    void flag(const wchar_t* k, bool v) { key(k); s += v ? L"true" : L"false"; }
    std::wstring wrap() const { return L"    {" + s + L"}"; }
};

void App::ExportData() {
    ScopedTimerPause pause(m_hwnd, 1, m_interval);
    wchar_t file[MAX_PATH] = L"netlurker.csv";
    OPENFILENAMEW ofn;
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = m_hwnd;

    std::wstring filt = Tr(L"HTML security report|*.html|CSV file|*.csv|JSON file|*.json|Text report|*.txt|All files|*.*|");
    for (auto& ch : filt) if (ch == L'|') ch = L'\0';
    ofn.lpstrFilter = filt.c_str();
    ofn.lpstrFile = file;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrDefExt = L"csv";
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
    if (!GetSaveFileNameW(&ofn)) return;

    std::wstring path = file;
    const bool asJson = (ToLower(path).find(L".json") != std::wstring::npos);
    const bool asHtml = (ToLower(path).find(L".html") != std::wstring::npos);
    const bool asTxt  = (ToLower(path).find(L".txt") != std::wstring::npos);
    std::wstring out;

    auto esc = [](std::wstring s) {
        for (auto& ch : s) if (ch == L';' || ch == L'\n' || ch == L'\r') ch = L' ';
        return s;
    };
    auto hesc = [](const std::wstring& s) {
        std::wstring r;
        r.reserve(s.size());
        for (wchar_t ch : s) {
            switch (ch) {
                case L'&': r += L"&amp;"; break;
                case L'<': r += L"&lt;"; break;
                case L'>': r += L"&gt;"; break;
                case L'"': r += L"&quot;"; break;
                default:   r += ch;
            }
        }
        return r;
    };

    wchar_t dstr[96] = { 0 };
    {
        wchar_t tstr[64] = { 0 };
        if (!GetDateFormatW(LOCALE_USER_DEFAULT, DATE_SHORTDATE, nullptr, nullptr, dstr, 96))
            swprintf(dstr, 96, L"%d.%d.%d", 1, 1, 1970);
        if (GetTimeFormatW(LOCALE_USER_DEFAULT, 0, nullptr, nullptr, tstr, 64))
            wcscat_s(dstr, 96, std::wstring(L" " + std::wstring(tstr)).c_str());
    }

    if (asHtml) {
        int danger = 0, warn = 0, pub = 0, listen = 0;
        for (const auto& c : m_rows) {
            if (c.risk == Risk::Danger) danger++;
            else if (c.risk == Risk::Warn) warn++;
            if (c.isRemotePublic) pub++;
            if (c.IsListening()) listen++;
        }
        const std::wstring riskLabel = danger ? Tr(L"HIGH") : warn ? Tr(L"MEDIUM") : Tr(L"LOW");
        const std::wstring riskColor = danger ? L"#e5484d" : warn ? L"#f5a623" : L"#30a46c";

        std::wstring h;
        auto add = [&](const std::wstring& x) { h += x; };
        add(std::wstring(L"<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">"));
        add(std::wstring(L"<title>NetLurker Investigation Report</title><style>"));
        add(std::wstring(L"body{background:#0e1116;color:#dbe2ea;font-family:'Segoe UI',Arial,sans-serif;margin:0;padding:24px;}"));
        add(std::wstring(L"h1{color:#6cb6ff;margin:0 0 4px 0;}h2{color:#9fc2e8;border-bottom:1px solid #2a3138;padding-bottom:6px;}"));
        add(std::wstring(L".sub{color:#7d8791;margin-bottom:24px;}table{border-collapse:collapse;width:100%;font-size:13px;}"));
        add(std::wstring(L"th{background:#151a21;color:#8fa2b8;text-align:left;padding:6px 8px;border:1px solid #232a33;}"));
        add(std::wstring(L"td{padding:5px 8px;border:1px solid #232a33;vertical-align:top;}"));
        add(std::wstring(L".risk{display:inline-block;padding:2px 8px;border-radius:10px;font-weight:bold;}"));
        add(std::wstring(L".hi{color:#e5484d;}.med{color:#f5a623;}.ok{color:#30a46c;}"));
        add(std::wstring(L".kpi{display:inline-block;background:#151a21;border:1px solid #232a33;border-radius:8px;padding:10px 16px;margin:4px;}"));
        add(std::wstring(L".kpi b{display:block;font-size:20px;}.foot{color:#7d8791;margin-top:28px;font-size:12px;}"));
        add(std::wstring(L"</style></head><body>"));
        add(std::wstring(L"<h1>NETLURKER INVESTIGATION REPORT</h1>"));
        add(std::wstring(L"<div class=\"sub\">") + Tr(L"Generated: ") + dstr);
        add(std::wstring(L" &nbsp;&bull;&nbsp; ") + Tr(L"Risk level: "));
        add(std::wstring(L"<span style=\"color:") + riskColor + L";font-weight:bold\">" + riskLabel + L"</span></div>");
        if (m_demo)
            add(std::wstring(L"<div style=\"background:#151a21;border:1px solid #6cb6ff;border-radius:8px;padding:10px 14px;margin:12px 0;color:#6cb6ff;font-weight:bold\">⚠ ") +
                Tr(L"DEMO MODE — this report contains sample data, not real system data.") + L"</div>");
        add(std::wstring(L"<div>"));
        add(std::wstring(L"<div class=\"kpi\"><b>") + std::to_wstring((int)m_rows.size()) + L"</b>" + Tr(L"open sockets") + L"</div>");
        add(std::wstring(L"<div class=\"kpi\"><b>") + std::to_wstring(pub) + L"</b>" + Tr(L"internet connections") + L"</div>");
        add(std::wstring(L"<div class=\"kpi\"><b>") + std::to_wstring(listen) + L"</b>" + Tr(L"listening ports") + L"</div>");
        add(std::wstring(L"<div class=\"kpi\"><b style=\"color:#f5a623\">") + std::to_wstring(warn) + L"</b>" + Tr(L"suspicious") + L"</div>");
        add(std::wstring(L"<div class=\"kpi\"><b style=\"color:#e5484d\">") + std::to_wstring(danger) + L"</b>" + Tr(L"critical") + L"</div>");
        add(std::wstring(L"</div>"));

        add(std::wstring(L"<h2>") + Tr(L"Connections") + L"</h2><table><tr><th>" + Tr(L"Application") + L"</th><th>PID</th><th>");
        add(std::wstring(Tr(L"Signature")) + L"</th><th>" + Tr(L"Destination") + L"</th><th>" + Tr(L"Service") + L"</th><th>");
        add(std::wstring(Tr(L"Country")) + L"</th><th>" + Tr(L"Organization") + L"</th><th>" + Tr(L"Domain") + L"</th><th>");
        add(std::wstring(Tr(L"Threat")) + L"</th><th>VirusTotal</th><th>" + Tr(L"Risk") + L"</th></tr>");
        if (m_tab == Tab::Conns) {
            for (int idx : m_view) {
                const Conn& c = m_rows[idx];
                const wchar_t* svc = PortServiceName(c.IsListening() ? c.localPort : c.remotePort);
                std::wstring rl = (c.risk == Risk::Danger) ? Tr(L"CRITICAL")
                                : (c.risk == Risk::Warn) ? Tr(L"SUSPICIOUS") : Tr(L"NORMAL");
                const std::wstring rc = (c.risk == Risk::Danger) ? L"hi" : (c.risk == Risk::Warn) ? L"med" : L"ok";
                add(std::wstring(L"<tr><td>") + hesc(c.procName) + L"</td><td>" + std::to_wstring(c.pid) + L"</td><td>");
                add(hesc(CellText(c, C_SIGN)) + L"</td><td>" + hesc(c.RemoteText()) + L"</td><td>");
                add(hesc(svc ? svc : L"") + L"</td><td>" + hesc(c.country) + L"</td><td>" + hesc(c.org));
                add(std::wstring(L"</td><td>") + hesc(c.domain) + L"</td><td>");
                if (c.threatScore >= 0) add(std::to_wstring(c.threatScore) + L"/100");
                if (!c.threatDnsbl.empty() && c.threatDnsbl != L"—") {
                    if (c.threatScore >= 0) add(std::wstring(L" &middot; "));
                    add(hesc(c.threatDnsbl));
                }
                add(std::wstring(L"</td><td>"));
                if (c.vtTotal) add(std::to_wstring(c.vtMalicious) + L"/" + std::to_wstring(c.vtTotal));
                add(std::wstring(L"</td><td><span class=\"risk ") + rc + L"\">" + hesc(rl) + L"</span></td></tr>");
            }
        }
        add(std::wstring(L"</table>"));

        add(std::wstring(L"<h2>") + Tr(L"Behavioral anomaly") + L"</h2>");
        if (m_anomAlerts.empty()) {
            add(std::wstring(L"<p>") + Tr(L"No anomalies detected.") + L"</p>");
        } else {
            add(std::wstring(L"<table><tr><th>") + Tr(L"Process") + L"</th><th>" + Tr(L"Baseline") + L"</th><th>");
            add(std::wstring(Tr(L"Current")) + L"</th><th>" + Tr(L"Deviation") + L"</th></tr>");
            for (const auto& kv : m_anomAlerts) {
                add(std::wstring(L"<tr><td>") + hesc(kv.second.name) + L"</td><td>");
                add(std::to_wstring((int)kv.second.baseline) + L" " + Tr(L"conn/min") + L"</td><td>");
                add(std::to_wstring((int)kv.second.current) + L" " + Tr(L"conn/min") + L"</td><td class=\"hi\">+");
                add(std::to_wstring((std::max)(0, kv.second.pct)) + L"%</td></tr>");
            }
            add(std::wstring(L"</table>"));
        }
        add(std::wstring(L"<div class=\"foot\">NetLurker &mdash; ") + Tr(L"Windows Network Intelligence"));
        add(std::wstring(L" &bull; ") + Tr(L"This report is based on heuristics; it is not a definitive verdict.") + L"</div>");
        add(std::wstring(L"</body></html>"));

        std::string utf8 = Narrow(h);
        HANDLE hf = CreateFileW(file, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                                FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hf == INVALID_HANDLE_VALUE) {
            MessageBoxW(m_hwnd, Tr(L"Could not write the file."), L"NetLurker", MB_ICONERROR);
            return;
        }
        DWORD wr = 0;
        WriteFile(hf, utf8.data(), (DWORD)utf8.size(), &wr, nullptr);
        CloseHandle(hf);
        Toast(Tr(L"HTML report saved: ") + path, clr::Green);
        return;
    }

    if (asTxt) {
        int danger = 0, warn = 0, pub = 0, listen = 0;
        for (const auto& c : m_rows) {
            if (c.risk == Risk::Danger) danger++;
            else if (c.risk == Risk::Warn) warn++;
            if (c.isRemotePublic) pub++;
            if (c.IsListening()) listen++;
        }
        std::wstring t;
        auto add = [&](const std::wstring& x) { t += x; };
        add(std::wstring(L"=======================================================================\r\n"));
        add(std::wstring(L"NETLURKER INVESTIGATION REPORT\r\n"));
        add(std::wstring(Tr(L"Generated: ")) + dstr + L"\r\n");
        if (m_demo) {
            add(std::wstring(L"⚠ "));
            add(Tr(L"DEMO MODE — this report contains sample data, not real system data."));
            add(std::wstring(L"\r\n"));
        }
        add(Tr(L"Risk level: "));
        add((danger ? Tr(L"HIGH") : warn ? Tr(L"MEDIUM") : Tr(L"LOW")) + std::wstring(L"\r\n"));
        add(std::wstring(L"=======================================================================\r\n"));
        add(std::wstring(L"  ") + Tr(L"open sockets") + L": " + std::to_wstring((int)m_rows.size()) + L"    ");
        add(std::wstring(Tr(L"internet connections")) + L": " + std::to_wstring(pub) + L"\r\n");
        add(std::wstring(L"  ") + Tr(L"listening ports") + L": " + std::to_wstring(listen) + L"    ");
        add(std::wstring(Tr(L"suspicious")) + L": " + std::to_wstring(warn) + L"    ");
        add(std::wstring(Tr(L"critical")) + L": " + std::to_wstring(danger) + L"\r\n\r\n");
        add(std::wstring(L"--- ") + Tr(L"Connections") + L" ---\r\n");
        if (m_tab == Tab::Conns) {
            for (int idx : m_view) {
                const Conn& c = m_rows[idx];
                const wchar_t* svc = PortServiceName(c.IsListening() ? c.localPort : c.remotePort);
                add(c.procName + L" [pid " + std::to_wstring(c.pid) + L"] " + CellText(c, C_SIGN) + L"\r\n");
                add(std::wstring(L"  ") + Tr(L"Destination") + L": " + c.RemoteText());
                if (svc && *svc) add(std::wstring(L" (") + std::wstring(svc) + L")");
                add(std::wstring(L"\r\n"));
                add(std::wstring(L"  ") + Tr(L"Location") + L": " + c.country + L"  " + Tr(L"Organization") + L": " + c.org + L"\r\n");
                if (!c.domain.empty()) add(std::wstring(L"  ") + Tr(L"Domain") + L": " + c.domain + L"\r\n");
                bool anyThreat = false;
                if (c.threatScore >= 0) {
                    add(std::wstring(L"  ") + Tr(L"Threat") + L": " + std::to_wstring(c.threatScore) + L"/100");
                    anyThreat = true;
                }
                if (!c.threatDnsbl.empty() && c.threatDnsbl != L"—") {
                    add(std::wstring(L"  ") + Tr(L"blacklists") + L": " + c.threatDnsbl);
                    anyThreat = true;
                }
                if (anyThreat) add(std::wstring(L"\r\n"));
                if (c.vtTotal) add(std::wstring(L"  VirusTotal: ") + std::to_wstring(c.vtMalicious) + L"/" + std::to_wstring(c.vtTotal) + L"\r\n");
                add(std::wstring(L"  ") + Tr(L"Risk") + L": ");
                add((c.risk == Risk::Danger) ? Tr(L"CRITICAL") : (c.risk == Risk::Warn) ? Tr(L"SUSPICIOUS") : Tr(L"NORMAL"));
                if (!c.riskReason.empty()) add(std::wstring(L" — ") + c.riskReason);
                add(std::wstring(L"\r\n\r\n"));
            }
        }
        add(std::wstring(L"--- ") + Tr(L"Behavioral anomaly") + L" ---\r\n");
        if (m_anomAlerts.empty()) {
            add(Tr(L"No anomalies detected.") + std::wstring(L"\r\n"));
        } else {
            for (const auto& kv : m_anomAlerts) {
                add(std::wstring(L"  ") + kv.second.name + L": " + Tr(L"Baseline") + L" ");
                add(std::to_wstring((int)kv.second.baseline) + L" " + Tr(L"conn/min") + L" -> ");
                add(std::to_wstring((int)kv.second.current) + L" " + Tr(L"conn/min") + L" (+");
                add(std::to_wstring((std::max)(0, kv.second.pct)) + L"%)\r\n");
            }
        }
        add(std::wstring(L"-----------------------------------------------------------------------\r\n"));
        add(std::wstring(L"NetLurker — ") + Tr(L"Windows Network Intelligence") + L"\r\n");
        add(std::wstring(Tr(L"This report is based on heuristics; it is not a definitive verdict.")) + L"\r\n");

        std::string utf8 = Narrow(t);
        HANDLE hf = CreateFileW(file, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                                FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hf == INVALID_HANDLE_VALUE) {
            MessageBoxW(m_hwnd, Tr(L"Could not write the file."), L"NetLurker", MB_ICONERROR);
            return;
        }
        DWORD wr = 0;
        const unsigned char bom[3] = { 0xEF, 0xBB, 0xBF };
        WriteFile(hf, bom, 3, &wr, nullptr);
        WriteFile(hf, utf8.data(), (DWORD)utf8.size(), &wr, nullptr);
        CloseHandle(hf);
        Toast(Tr(L"Text report saved: ") + path, clr::Green);
        return;
    }

    if (asJson) {
        out = L"{\n  \"tool\": \"NetLurker\",\n  \"tab\": \"";
        out += (m_tab == Tab::Conns ? L"connections" : m_tab == Tab::Apps ? L"applications" :
                m_tab == Tab::History ? L"history" : L"stats");
        out += L"\",\n  \"generated\": \"" + Widen(json::Escape(Narrow(dstr))) + L"\",\n";
        out += std::wstring(L"  \"demo\": ") + (m_demo ? L"true" : L"false") + L",\n";
        out += L"  \"rows\": [\n";
        bool first = true;
        if (m_tab == Tab::Apps) {
            for (int idx : m_view) {
                const AppRow& a = m_apps[idx];
                if (!first) out += L",\n";
                first = false;
                JsonObj o;
                o.str(L"app", a.name);
                o.num(L"pid", (long long)a.pid);
                o.str(L"publisher", a.publisher);
                o.str(L"signature", a.SignText());
                o.str(L"user", a.user);
                o.str(L"services", a.services);
                o.num(L"connections", a.conns);
                o.num(L"internet", a.publicConns);
                o.num(L"down_bps", (long long)a.rateIn);
                o.num(L"up_bps", (long long)a.rateOut);
                o.num(L"bytes_in", a.bytesIn);
                o.num(L"bytes_out", a.bytesOut);
                o.num(L"risk", a.riskScore);
                o.real(L"cpu_percent", a.cpu);
                o.num(L"ram_bytes", a.ram);
                o.num(L"threads", (long long)a.threads);
                o.num(L"handles", (long long)a.handles);
                o.flag(L"suspended", a.suspended);
                o.flag(L"elevated", a.elevated);
                o.str(L"integrity", IntegrityText(a.integrity));
                o.str(L"countries", a.countries);
                o.str(L"path", a.path);
                o.str(L"domain", a.domain);
                out += o.wrap();
            }
        } else if (m_tab == Tab::History) {
            const auto& ents = m_hist.Entries();
            for (int idx : m_view) {
                const HistEntry& h = ents[idx];
                if (!first) out += L",\n";
                first = false;
                JsonObj o;
                o.str(L"time", h.TimeText());
                o.str(L"app", h.proc);
                o.num(L"pid", (long long)h.pid);
                o.str(L"proto", h.proto);
                o.str(L"remote", h.remoteIp);
                o.num(L"port", (long long)h.remotePort);
                o.str(L"country", h.country);
                o.str(L"org", h.org);
                o.str(L"host", h.host);
                o.str(L"module", h.module);
                o.str(L"domain", h.domain);
                o.str(L"banner", h.banner);
                o.num(L"threat_score", (long long)h.threatScore);
                o.str(L"threat_dnsbl", h.threatDnsbl);
                o.str(L"cert_issuer", h.certIssuer);
                o.flag(L"cert_selfsigned", h.certSelfSigned);
                o.num(L"bytes_in", h.bytesIn);
                o.num(L"bytes_out", h.bytesOut);
                o.num(L"duration_ms", h.DurationMs());
                o.flag(L"active", h.active);
                o.num(L"risk", h.riskScore);
                o.str(L"risk_reason", h.riskReason);
                o.str(L"path", h.path);
                out += o.wrap();
            }
        } else {
            for (int idx : m_view) {
                const Conn& c = m_rows[idx];
                if (!first) out += L",\n";
                first = false;
                JsonObj o;
                o.str(L"app", c.procName);
                o.num(L"pid", (long long)c.pid);
                o.str(L"publisher", c.publisher);
                o.str(L"signature", CellText(c, C_SIGN));
                o.str(L"user", c.user);
                o.str(L"proto", c.ProtoText());
                o.str(L"local", c.LocalText());
                o.str(L"remote", c.RemoteText());
                o.num(L"remote_port", (long long)c.remotePort);
                o.str(L"state", c.StateText());
                o.str(L"country", c.country);
                o.str(L"country_code", c.countryCode);
                o.str(L"city", c.city);
                o.str(L"org", c.org);
                o.str(L"asn", c.asn);
                o.str(L"host", c.host);
                o.str(L"module", c.module);
                o.str(L"domain", c.domain);
                o.str(L"banner", c.banner);
                o.str(L"rdap_org", c.rdapOrg);
                o.str(L"rdap_cidr", c.rdapCidr);
                o.str(L"rdap_abuse", c.rdapAbuse);
                o.num(L"vt_malicious", (long long)c.vtMalicious);
                o.num(L"vt_suspicious", (long long)c.vtSuspicious);
                o.num(L"vt_total", (long long)c.vtTotal);
                o.num(L"vt_reputation", (long long)c.vtReputation);
                o.flag(L"hosting", c.isHosting);
                o.flag(L"proxy", c.isProxy);
                o.num(L"threat_score", (long long)c.threatScore);
                o.str(L"threat_dnsbl", c.threatDnsbl);
                o.num(L"threat_passive_dns", (long long)c.threatPdns);
                o.str(L"cert_issuer", c.certIssuer);
                o.str(L"cert_subject", c.certSubject);
                o.flag(L"cert_selfsigned", c.certSelfSigned);
                o.flag(L"cert_expired", c.certExpired);
                o.flag(L"cert_mismatch", c.certMismatch);
                o.num(L"rtt_ms", (long long)c.rttMs);
                o.num(L"down_bps", (long long)c.rateIn);
                o.num(L"up_bps", (long long)c.rateOut);
                o.num(L"bytes_in", c.bytesIn);
                o.num(L"bytes_out", c.bytesOut);
                o.num(L"age_ms", c.ageMs);
                o.num(L"risk", c.riskScore);
                o.str(L"risk_reason", c.riskReason);
                o.str(L"path", c.procPath);
                out += o.wrap();
            }
        }
        out += L"\n  ]\n}\n";
    } else {
        if (m_tab == Tab::Apps) {
            out = std::wstring(Tr(L"Application;PID;Publisher;Signature;User;Services;Connections;Internet;DownBps;UpBps;TotalBytes;CPU;MemoryBytes;Threads;Handles;Suspended;Elevated;IntegrityLevel;Countries;RiskScore;Risk;Path;Domain")) + L"\r\n";
            for (int idx : m_view) {
                const AppRow& a = m_apps[idx];
                out += esc(a.name) + L";" + std::to_wstring(a.pid) + L";" + esc(a.publisher) + L";" +
                       a.SignText() + L";" + esc(a.user) + L";" + esc(a.services) + L";" +
                       std::to_wstring(a.conns) + L";" + std::to_wstring(a.publicConns) + L";" +
                       std::to_wstring((long long)a.rateIn) + L";" + std::to_wstring((long long)a.rateOut) + L";" +
                       std::to_wstring(a.bytesIn + a.bytesOut) + L";" +
                       AppCellText(a, A_CPU) + L";" + std::to_wstring(a.ram) + L";" +
                       std::to_wstring(a.threads) + L";" + std::to_wstring(a.handles) + L";" +
                       (a.suspended ? Tr(L"yes") : Tr(L"no")) + L";" + (a.elevated ? Tr(L"yes") : Tr(L"no")) + L";" +
                       IntegrityText(a.integrity) + L";" + esc(a.countries) + L";" +
                       std::to_wstring(a.riskScore) + L";" + AppCellText(a, A_RISK) + L";" + esc(a.path) +
                       L";" + esc(a.domain) + L"\r\n";
            }
        } else if (m_tab == Tab::History) {
            const auto& ents = m_hist.Entries();
            out = std::wstring(Tr(L"Time;Application;PID;Proto;Remote;Port;Service;Country;Organization;Host;Domain;Banner;Module;ThreatScore;ThreatBlacklist;CertIssuer;BytesIn;BytesOut;DurationMs;State;RiskScore;Reason")) + L"\r\n";
            for (int idx : m_view) {
                const HistEntry& h = ents[idx];
                const wchar_t* svc = PortServiceName(h.remotePort);
                out += h.TimeText() + L";" + esc(h.proc) + L";" + std::to_wstring(h.pid) + L";" + h.proto + L";" +
                       h.remoteIp + L";" + std::to_wstring(h.remotePort) + L";" + (svc ? svc : L"") + L";" +
                       esc(h.country) + L";" + esc(h.org) + L";" + esc(h.host) + L";" +
                       esc(h.domain) + L";" + esc(h.banner) + L";" +
                       esc(h.module) + L";" +
                       (h.threatScore >= 0 ? std::to_wstring(h.threatScore) : L"") + L";" +
                       esc(h.threatDnsbl) + L";" + esc(h.certIssuer) + L";" +
                       std::to_wstring(h.bytesIn) + L";" + std::to_wstring(h.bytesOut) + L";" +
                       std::to_wstring(h.DurationMs()) + L";" + (h.active ? Tr(L"open") : Tr(L"closed")) + L";" +
                       std::to_wstring(h.riskScore) + L";" + esc(h.riskReason) + L"\r\n";
            }
        } else {
            out = std::wstring(Tr(L"Application;PID;Publisher;Signature;User;Proto;Local;Remote;Service;State;Country;City;Organization;ASN;Host;Domain;Banner;Module;ThreatScore;ThreatBlacklist;PassiveDNS;CertIssuer;CertCN;SelfSigned;CertExpired;RDAP;VT;DataCenter;Proxy;RTTms;DownBps;UpBps;TotalBytes;DurationMs;RiskScore;Risk;Reason;Path")) + L"\r\n";
            for (int idx : m_view) {
                const Conn& c = m_rows[idx];
                const wchar_t* svc = PortServiceName(c.IsListening() ? c.localPort : c.remotePort);
                out += esc(c.procName) + L";" + std::to_wstring(c.pid) + L";" + esc(c.publisher) + L";" +
                       CellText(c, C_SIGN) + L";" + esc(c.user) + L";" + c.ProtoText() + L";" +
                       c.LocalText() + L";" + c.RemoteText() + L";" + (svc ? svc : L"") + L";" +
                       c.StateText() + L";" + esc(c.country) + L";" + esc(c.city) + L";" +
                       esc(c.org) + L";" + esc(c.asn) + L";" + esc(c.host) + L";" +
                       esc(c.domain) + L";" + esc(c.banner) + L";" +
                       esc(c.module) + L";" +
                       (c.threatScore >= 0 ? std::to_wstring(c.threatScore) : L"") + L";" +
                       esc(c.threatDnsbl) + L";" + std::to_wstring(c.threatPdns) + L";" +
                       esc(c.certIssuer) + L";" + esc(c.certSubject) + L";" +
                       (c.certSelfSigned ? L"yes" : L"no") + L";" +
                       (c.certExpired ? L"yes" : L"no") + L";" +
                       esc(c.rdapOrg + L" " + c.rdapCidr) + L";" +
                       (c.vtTotal ? std::to_wstring(c.vtMalicious) + L"/" + std::to_wstring(c.vtTotal) : L"") + L";" +
                       (c.isHosting ? L"yes" : L"no") + L";" + (c.isProxy ? L"yes" : L"no") + L";" +
                       std::to_wstring(c.rttMs) + L";" +
                       std::to_wstring((long long)c.rateIn) + L";" + std::to_wstring((long long)c.rateOut) + L";" +
                       std::to_wstring(c.bytesIn + c.bytesOut) + L";" + std::to_wstring(c.ageMs) + L";" +
                       std::to_wstring(c.riskScore) + L";" + c.RiskText() + L";" + esc(c.riskReason) + L";" +
                       esc(c.procPath) + L"\r\n";
            }
        }
    }

    std::string utf8 = Narrow(out);
    HANDLE hf = CreateFileW(file, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf == INVALID_HANDLE_VALUE) {
        MessageBoxW(m_hwnd, Tr(L"Could not write the file."), L"NetLurker", MB_ICONERROR);
        return;
    }
    DWORD wr = 0;
    if (!asJson && !asHtml) {
        const unsigned char bom[3] = { 0xEF, 0xBB, 0xBF };
        WriteFile(hf, bom, 3, &wr, nullptr);
    }
    WriteFile(hf, utf8.data(), (DWORD)utf8.size(), &wr, nullptr);
    CloseHandle(hf);
}

static void PostAiResult(HWND hwnd, bool ok, std::wstring text) {
    auto* payload = new std::wstring(std::move(text));
    if (!hwnd || !IsWindow(hwnd) ||
        !PostMessageW(hwnd, WM_APP_AI_DONE, ok ? 1 : 0, (LPARAM)payload))
        delete payload;
}

void App::RunAiAnalysis(bool bulk) {
    m_showDetail = true;
    m_aiScroll = 0;
    AiConfig cfg = LoadAiConfig();
    m_aiKeyMissing = cfg.apiKey.empty();
    if (m_aiKeyMissing)
        Toast(Tr(L"No AI API key configured — running the offline heuristic engine instead (Settings → API key)."),
              clr::Yellow);

    if (bulk) {
        std::vector<Conn> top;
        for (const auto& c : m_rows) if (c.riskScore >= 25) top.push_back(c);
        std::sort(top.begin(), top.end(), [](const Conn& a, const Conn& b) {
            return a.riskScore > b.riskScore;
        });
        if (top.size() > 8) top.resize(8);
        if (top.empty()) {
            std::lock_guard<std::mutex> lk(m_aiMtx);
            m_aiTitle = Tr(L"Bulk analysis");
            m_aiText  = Tr(L"No connection above 25 points right now. The system looks clean.");
            Layout();
            InvalidateRect(m_hwnd, nullptr, FALSE);
            return;
        }
        std::wstring prompt = BuildBulkPrompt(top);
        if (!cfg.Valid()) {
            std::lock_guard<std::mutex> lk(m_aiMtx);
            m_aiTitle = Tr(L"Bulk offline analysis (") + std::to_wstring(top.size()) + Tr(L" connections)");
            std::wstring txt;
            for (const auto& c : top) txt += LocalHeuristicAnalysis(c) + L"\n\n──────────\n\n";
            m_aiText = txt;
            Layout();
            InvalidateRect(m_hwnd, nullptr, FALSE);
            return;
        }
        {
            std::lock_guard<std::mutex> lk(m_aiMtx);
            if (m_aiBusy) return;
            m_aiBusy = true;
            m_aiTitle = Tr(L"AI bulk analysis (") + std::to_wstring(top.size()) + Tr(L" connections)");
            m_aiText  = Tr(L"Analyzing…");
        }
        Layout();
        InvalidateRect(m_hwnd, nullptr, FALSE);
        m_lastAiPrompt = prompt;
        m_lastAiProc.clear();
        HWND hwnd = m_hwnd;
        AnalyzeAsync(cfg, prompt, [hwnd](bool ok, std::wstring text) {
            PostAiResult(hwnd, ok, std::move(text));
        });
        return;
    }

    const Conn*      c = SelectedConn();
    const AppRow*    a = SelectedApp();
    const HistEntry* h = SelectedHist();
    if (!c && !a && !h) {
        std::lock_guard<std::mutex> lk(m_aiMtx);
        m_aiTitle = Tr(L"AI / Analysis");
        m_aiText  = Tr(L"Select a row from the list first.");
        Layout();
        InvalidateRect(m_hwnd, nullptr, FALSE);
        return;
    }

    Conn subject;
    if (c) subject = *c;
    else {
        DWORD pid = a ? a->pid : h->pid;
        const Conn* best = nullptr;
        for (const auto& x : m_rows) {
            if (x.pid != pid) continue;
            if (!best || x.riskScore > best->riskScore ||
                (x.riskScore == best->riskScore && x.rateIn + x.rateOut > best->rateIn + best->rateOut))
                best = &x;
        }
        if (best) subject = *best;
        else if (h) {
            subject.procName   = h->proc;
            subject.procPath   = h->path;
            subject.pid        = h->pid;
            subject.remoteIp   = h->remoteIp;
            subject.remotePort = h->remotePort;
            subject.country    = h->country;
            subject.org        = h->org;
            subject.host       = h->host;
            subject.riskScore  = h->riskScore;
            subject.risk       = h->risk;
            subject.riskReason = h->riskReason;
            subject.bytesIn    = h->bytesIn;
            subject.bytesOut   = h->bytesOut;
        } else return;
    }
    m_lastAiProc = subject.procName;

    if (!cfg.Valid()) {
        std::lock_guard<std::mutex> lk(m_aiMtx);
        m_aiBusy = false;
        m_aiTitle = Tr(L"Offline heuristic analysis — ") + subject.procName;
        m_aiText  = LocalHeuristicAnalysis(subject);
        Layout();
        InvalidateRect(m_hwnd, nullptr, FALSE);
        return;
    }

    {
        std::lock_guard<std::mutex> lk(m_aiMtx);
        if (m_aiBusy) return;
        m_aiBusy  = true;
        m_aiTitle = Tr(L"AI analysis — ") + subject.procName;
        m_aiText  = Tr(L"Analyzing…");
    }
    Layout();
    InvalidateRect(m_hwnd, nullptr, FALSE);

    HWND hwnd = m_hwnd;
    ProcContext pctx;
    if (subject.pid) {
        ProcDetails d  = m_mon.Procs().Get(subject.pid);
        ProcRuntime rt = m_mon.Procs().Runtime(subject.pid);
        pctx.valid     = true;
        pctx.cmdline   = d.cmdline;
        pctx.integrity = IntegrityText(d.integrity);
        pctx.parent    = d.parentPid ? ((d.parentName.empty() ? std::wstring(L"PID ") : (d.parentName + L" #")) +
                                        std::to_wstring(d.parentPid)) : std::wstring();
        pctx.sha256    = d.sha256;
        pctx.product   = d.product.empty() ? d.description : d.product;
        pctx.version   = d.fileVersion;
        pctx.cpu       = rt.cpu;
        pctx.ram       = rt.workingSet;
        pctx.threads   = rt.threads;
        pctx.elevated  = d.elevated;
        pctx.suspended = rt.suspended;
        if (d.startTime) {
            unsigned long long nowUnix = (unsigned long long)time(nullptr) * 1000ull;
            if (nowUnix > d.startTime) pctx.uptimeMs = nowUnix - d.startTime;
        }
    }
    std::wstring prompt = BuildAnalysisPrompt(subject, m_rows, pctx);
    AnalyzeAsync(cfg, prompt, [hwnd](bool ok, std::wstring text) {
        PostAiResult(hwnd, ok, std::move(text));
    });
}

void App::OnAiDone(bool ok, std::wstring* text) {
    {
        std::lock_guard<std::mutex> lk(m_aiMtx);
        m_aiBusy = false;
        m_aiText = ok ? *text : (L"⚠ " + *text);
    }
    delete text;
    InvalidateRect(m_hwnd, nullptr, FALSE);
}

void App::Relaunch(bool asAdmin) {
    wchar_t path[MAX_PATH] = L"";
    GetModuleFileNameW(nullptr, path, MAX_PATH);
    ShellExecuteW(nullptr, asAdmin ? L"runas" : L"open", path, nullptr, nullptr, SW_SHOWNORMAL);
}

INT_PTR CALLBACK App::ElevateProc(HWND dlg, UINT msg, WPARAM wp, LPARAM lp) {
    static HBRUSH brBg = nullptr;
    switch (msg) {
        case WM_INITDIALOG: {
            if (!brBg) brBg = CreateSolidBrush(clr::Bg);
            SetDlgItemTextW(dlg, IDC_ST_ELEVATE, Tr(L"Administrator privileges required"));
            SetDlgItemTextW(dlg, IDC_ST_NOTICE,  Tr(L"NetLurker works without admin rights too; however, the following are only possible elevated:\n\n• Per-connection download/upload rate (KB/s) and RTT measurement\n• Terminating processes and process trees\n• Adding IP block rules to the Windows firewall\n• TCP/UDP table of all system processes\n\nNetLurker does not use elevation to collect data and does not modify your network configuration."));
            SetDlgItemTextW(dlg, IDC_BTN_ELEVATE, Tr(L"Continue as administrator"));
            SetDlgItemTextW(dlg, IDC_BTN_NORMAL,  Tr(L"Continue without elevation"));
            BOOL dark = TRUE;
            DwmSetWindowAttribute(dlg, 20, &dark, sizeof(dark));
            DwmSetWindowAttribute(dlg, 19, &dark, sizeof(dark));
            return TRUE;
        }
        case WM_CTLCOLORDLG:
        case WM_CTLCOLORBTN:
        case WM_CTLCOLORSTATIC: {
            HDC dc = (HDC)wp;
            SetTextColor(dc, clr::Text);
            SetBkColor(dc, clr::Bg);
            return (INT_PTR)brBg;
        }
        case WM_COMMAND:
            if (LOWORD(wp) == IDC_BTN_ELEVATE) { EndDialog(dlg, IDYES); return TRUE; }
            if (LOWORD(wp) == IDC_BTN_NORMAL)  { EndDialog(dlg, IDNO);  return TRUE; }
            if (LOWORD(wp) == IDCANCEL)        { EndDialog(dlg, IDNO);  return TRUE; }
            break;
    }
    return FALSE;
}

INT_PTR CALLBACK App::SettingsProc(HWND dlg, UINT msg, WPARAM wp, LPARAM lp) {
    auto* self = reinterpret_cast<App*>(GetWindowLongPtrW(dlg, GWLP_USERDATA));
    auto* layout = reinterpret_cast<SettingsDialogLayout*>(GetPropW(dlg, L"SettingsLayout"));
    HWND fields = layout ? layout->Body() : dlg;
    static HBRUSH brBg = nullptr, brEdit = nullptr;
    switch (msg) {
        case WM_INITDIALOG: {
            self = reinterpret_cast<App*>(lp);
            SetWindowLongPtrW(dlg, GWLP_USERDATA, lp);
            if (!brBg)   brBg   = CreateSolidBrush(clr::Bg);
            if (!brEdit) brEdit = CreateSolidBrush(clr::Surface);
            AiConfig cfg = LoadAiConfig(false);
            SetDlgItemTextW(fields, IDC_ED_ENDPOINT, cfg.endpoint.c_str());
            SetDlgItemTextW(fields, IDC_ED_MODEL,    cfg.model.c_str());
            SetDlgItemTextW(fields, IDC_ED_KEY,      cfg.apiKey.c_str());
            if (self) {
                CheckDlgButton(fields, IDC_CHK_GEO,    self->m_geoOnline  ? BST_CHECKED : BST_UNCHECKED);
                CheckDlgButton(fields, IDC_CHK_NOTIFY, self->m_notify     ? BST_CHECKED : BST_UNCHECKED);
                CheckDlgButton(fields, IDC_CHK_SOUND,  self->m_soundAlert ? BST_CHECKED : BST_UNCHECKED);
                CheckDlgButton(fields, IDC_CHK_CONFIRM,self->m_confirmKill ? BST_CHECKED : BST_UNCHECKED);
                CheckDlgButton(fields, IDC_CHK_THREAT, self->m_threatOnline ? BST_CHECKED : BST_UNCHECKED);
                CheckDlgButton(fields, IDC_CHK_RDAP,   self->m_rdapOnline   ? BST_CHECKED : BST_UNCHECKED);
                CheckDlgButton(fields, IDC_CHK_BANNER, self->m_bannerOnline ? BST_CHECKED : BST_UNCHECKED);
                SetDlgItemInt(fields, IDC_ED_INTERVAL,  (UINT)(self->m_interval / 100), FALSE);
                SetDlgItemInt(fields, IDC_ED_RISKMIN,   (UINT)self->m_notifyMin, FALSE);
                SetDlgItemTextW(fields, IDC_ED_ABUSEKEY, self->m_abuseKey.c_str());
                SetDlgItemTextW(fields, IDC_ED_VTKEY,    self->m_vtKey.c_str());
                int langIdx = 0;
                for (const auto& l : I18nLanguages()) {
                    int i = (int)SendDlgItemMessageW(fields, IDC_CMB_LANG, CB_ADDSTRING, 0,
                                                     (LPARAM)l.second.c_str());
                    if (l.first == self->m_lang) langIdx = i;
                }
                SendDlgItemMessageW(fields, IDC_CMB_LANG, CB_SETCURSEL, (WPARAM)langIdx, 0);
            }

            SetWindowTextW(dlg, Tr(L"NetLurker - Settings"));
            SetDlgItemTextW(fields, IDC_ST_ENDPOINT, Tr(L"AI endpoint (OpenAI-compatible chat/completions URL):"));
            SetDlgItemTextW(fields, IDC_ST_MODEL,    Tr(L"Model:"));
            SetDlgItemTextW(fields, IDC_ST_INTERVAL, Tr(L"Refresh (x100 ms):"));
            SetDlgItemTextW(fields, IDC_ST_KEY,      Tr(L"API key:"));
            SetDlgItemTextW(fields, IDC_ST_RISKMIN,  Tr(L"Notification risk threshold (20-100):"));
            SetDlgItemTextW(fields, IDC_ST_THREAT,   Tr(L"THREAT INTELLIGENCE"));
            SetDlgItemTextW(fields, IDC_ST_ABUSEKEY, Tr(L"AbuseIPDB API key (optional, free at abuseipdb.com):"));
            SetDlgItemTextW(fields, IDC_ST_VTKEY,    Tr(L"VirusTotal API key (empty = off; free plan: 4 lookups/minute):"));
            SetDlgItemTextW(fields, IDC_ST_LANG,     Tr(L"Language:"));
            SetDlgItemTextW(fields, IDC_ST_INFO,     Tr(L"The AI key is stored in %APPDATA%\\NetLurker\\config.ini. If left empty, the OPENAI_API_KEY environment variable is used; otherwise local heuristic analysis runs."));
            SetDlgItemTextW(fields, IDC_CHK_GEO,     Tr(L"Enable IP geolocation/org lookup (ip-api.com)"));
            SetDlgItemTextW(fields, IDC_CHK_NOTIFY,  Tr(L"Show desktop notification on risky connection"));
            SetDlgItemTextW(fields, IDC_CHK_SOUND,   Tr(L"Play alert sound on notification"));
            SetDlgItemTextW(fields, IDC_CHK_CONFIRM, Tr(L"Ask for confirmation before killing a process"));
            SetDlgItemTextW(fields, IDC_CHK_THREAT,  Tr(L"Enable threat intelligence (AbuseIPDB + DNS blacklists + CIRCL passive DNS + TLS certificate analysis)"));
            SetDlgItemTextW(fields, IDC_CHK_RDAP,    Tr(L"Enable RDAP ownership lookup (network/org/contact/registration date)"));
            SetDlgItemTextW(fields, IDC_CHK_BANNER,  Tr(L"Enable HTTP banner detection (remote server software)"));
            SetDlgItemTextW(dlg, IDOK,            Tr(L"Save"));
            SetDlgItemTextW(dlg, IDCANCEL,        Tr(L"Cancel"));
            BOOL dark = TRUE;
            DwmSetWindowAttribute(dlg, 20, &dark, sizeof(dark));
            DwmSetWindowAttribute(dlg, 19, &dark, sizeof(dark));
            layout = new SettingsDialogLayout(dlg, brBg);
            if (!SetPropW(dlg, L"SettingsLayout", layout)) { delete layout; EndDialog(dlg, -1); return TRUE; }
            if (!layout->Initialize()) { EndDialog(dlg, -1); return TRUE; }
            return TRUE;
        }
        case WM_SIZE:
            if (layout) layout->Layout();
            return TRUE;
        case WM_GETMINMAXINFO:
            if (layout) layout->MinMax(reinterpret_cast<MINMAXINFO*>(lp));
            return TRUE;
        case WM_DPICHANGED:
            if (layout) layout->ChangeDpi(HIWORD(wp), *reinterpret_cast<RECT*>(lp));
            return TRUE;
        case WM_SETTINGCHANGE:
        case WM_DISPLAYCHANGE:
            if (layout) { RECT r{}; GetWindowRect(dlg, &r); layout->Clamp(r); layout->Layout(); }
            break;
        case WM_NCDESTROY:
            RemovePropW(dlg, L"SettingsLayout");
            delete layout;
            break;
        case WM_CTLCOLORDLG:
        case WM_CTLCOLORBTN:
        case WM_CTLCOLORSTATIC: {
            HDC dc = (HDC)wp;
            SetTextColor(dc, clr::Text);
            SetBkColor(dc, clr::Bg);
            return (INT_PTR)brBg;
        }
        case WM_CTLCOLOREDIT: {
            HDC dc = (HDC)wp;
            SetTextColor(dc, clr::Text);
            SetBkColor(dc, clr::Surface);
            return (INT_PTR)brEdit;
        }
        case WM_COMMAND:
            if (LOWORD(wp) == IDOK && self && fields) {
                AiConfig cfg;
                wchar_t buf[1024];
                GetDlgItemTextW(fields, IDC_ED_ENDPOINT, buf, 1024); cfg.endpoint = Trim(buf);
                GetDlgItemTextW(fields, IDC_ED_MODEL,    buf, 1024); cfg.model    = Trim(buf);
                GetDlgItemTextW(fields, IDC_ED_KEY,      buf, 1024); cfg.apiKey   = Trim(buf);
                auto read = [&](int id) { GetDlgItemTextW(fields, id, buf, 1024); return Trim(buf); };
                const auto abuseKey = read(IDC_ED_ABUSEKEY), vtKey = read(IDC_ED_VTKEY);
                BOOL intervalValid = FALSE, riskValid = FALSE;
                const UINT interval = GetDlgItemInt(fields, IDC_ED_INTERVAL, &intervalValid, FALSE);
                const UINT risk = GetDlgItemInt(fields, IDC_ED_RISKMIN, &riskValid, FALSE);
                if (!intervalValid || interval < 5 || interval > 100 || !riskValid || risk < 20 || risk > 100) {
                    MessageBoxW(dlg, Tr(L"Refresh must be 5-100 (x100 ms), and notification risk must be 20-100."), Tr(L"Settings"), MB_OK | MB_ICONWARNING);
                    SetFocus(GetDlgItem(fields, (!intervalValid || interval < 5 || interval > 100) ? IDC_ED_INTERVAL : IDC_ED_RISKMIN));
                    return TRUE;
                }
                http::ParsedUrl endpoint;
                if ((!cfg.apiKey.empty() || !AiEnvironmentKey().empty()) &&
                    (!http::ParseUrl(cfg.endpoint, endpoint) || (!endpoint.secure && !endpoint.Loopback()) || cfg.model.empty())) {
                    MessageBoxW(dlg, Tr(L"Enter a valid HTTPS AI endpoint and a model. HTTP is allowed only for loopback servers."), Tr(L"Settings"), MB_OK | MB_ICONWARNING);
                    SetFocus(GetDlgItem(fields, cfg.model.empty() ? IDC_ED_MODEL : IDC_ED_ENDPOINT));
                    return TRUE;
                }
                const auto langs = I18nLanguages();
                const int li = (int)SendDlgItemMessageW(fields, IDC_CMB_LANG, CB_GETCURSEL, 0, 0);
                const auto language = li >= 0 && li < (int)langs.size() ? langs[li].first : self->m_lang;
                std::vector<IniValue> values{
                    {L"ai", L"endpoint", cfg.endpoint}, {L"ai", L"model", cfg.model}, {L"ai", L"api_key", cfg.apiKey},
                    {L"threat", L"abusekey", abuseKey}, {L"threat", L"vtkey", vtKey},
                    {L"ui", L"lang", language}, {L"ui", L"interval", std::to_wstring(interval * 100)},
                    {L"ui", L"notifymin", std::to_wstring(risk)}
                };
                for (const auto& field : std::vector<std::pair<int, const wchar_t*>>{
                    {IDC_CHK_GEO, L"geo"}, {IDC_CHK_NOTIFY, L"notify"}, {IDC_CHK_SOUND, L"sound"},
                    {IDC_CHK_CONFIRM, L"confirmkill"}, {IDC_CHK_THREAT, L"threat"},
                    {IDC_CHK_RDAP, L"rdap"}, {IDC_CHK_BANNER, L"banner"}})
                    values.push_back({L"ui", field.second, IsDlgButtonChecked(fields, field.first) == BST_CHECKED ? L"1" : L"0"});
                if (!UpdateIniAtomically(ConfigPath(), values)) {
                    MessageBoxW(dlg, Tr(L"Settings could not be saved. Check available disk space and config.ini permissions, then try again. Your changes are still in this dialog."), Tr(L"Settings"), MB_OK | MB_ICONERROR);
                    return TRUE;
                }
                if (self) {
                    self->m_aiKeyMissing = !LoadAiConfig().Valid();
                    self->m_geoOnline  = (IsDlgButtonChecked(fields, IDC_CHK_GEO) == BST_CHECKED);
                    self->m_notify     = (IsDlgButtonChecked(fields, IDC_CHK_NOTIFY) == BST_CHECKED);
                    self->m_soundAlert = (IsDlgButtonChecked(fields, IDC_CHK_SOUND) == BST_CHECKED);
                    self->m_confirmKill= (IsDlgButtonChecked(fields, IDC_CHK_CONFIRM) == BST_CHECKED);
                    self->m_threatOnline = (IsDlgButtonChecked(fields, IDC_CHK_THREAT) == BST_CHECKED);
                    self->m_rdapOnline   = (IsDlgButtonChecked(fields, IDC_CHK_RDAP) == BST_CHECKED);
                    self->m_bannerOnline = (IsDlgButtonChecked(fields, IDC_CHK_BANNER) == BST_CHECKED);
                    self->m_abuseKey = abuseKey;
                    self->m_vtKey = vtKey;
                    self->m_vtOnline = !self->m_vtKey.empty();
                    self->m_lang = language;
                    I18nSetLanguage(self->m_lang);
                    I18nLoadFrom(ExeDir() + L"\\lang");
                    I18nLoadFrom(AppDataDir() + L"\\lang");
                    InvalidateRect(self->m_hwnd, nullptr, TRUE);
                    self->m_geo.SetOnline(self->m_geoOnline);
                    self->m_threat.SetOnline(self->m_threatOnline || self->m_rdapOnline || self->m_vtOnline);
                    self->m_threat.SetRdapOnline(self->m_rdapOnline);
                    self->m_threat.SetAbuseKey(self->m_abuseKey);
                    self->m_threat.SetVtKey(self->m_vtKey);
                    self->m_cert.SetOnline(self->m_threatOnline);
                    self->m_banner.SetOnline(self->m_bannerOnline);
                    self->m_interval = (int)interval * 100;
                    self->m_notifyMin = (int)risk;
                    self->m_effInterval = self->m_interval;
                    SetTimer(self->m_hwnd, 1, self->m_interval, nullptr);
                }
                EndDialog(dlg, IDOK);
                return TRUE;
            }
            if (LOWORD(wp) == IDCANCEL) { EndDialog(dlg, IDCANCEL); return TRUE; }
            break;
    }
    return FALSE;
}

void App::ShowSettings() {

    if (DialogBoxParamW(m_inst, MAKEINTRESOURCEW(IDD_SETTINGS), m_hwnd, &App::SettingsProc, (LPARAM)this) == IDOK) {
        SetWindowTextW(m_hwnd, Tr(L"NetLurker — Network & Process Monitor"));
        RemoveTray();
        SetupTray();
        Layout();
        RebuildView();
    }
    InvalidateRect(m_hwnd, nullptr, FALSE);
}

LRESULT CALLBACK App::SearchProc(HWND h, UINT msg, WPARAM wp, LPARAM lp) {
    App* self = g_app;
    if (msg == WM_KEYDOWN && (wp == VK_ESCAPE || wp == VK_DOWN || wp == VK_UP || wp == VK_RETURN)) {
        if (self) {
            if (wp == VK_ESCAPE) SetWindowTextW(h, L"");
            SetFocus(self->m_hwnd);
            if (wp != VK_ESCAPE) self->OnKeyDown(wp);
        }
        return 0;
    }
    if (msg == WM_SETFOCUS || msg == WM_KILLFOCUS) {
        if (self) InvalidateRect(self->m_hwnd, &self->m_rcToolbar, FALSE);
    }
    return CallWindowProcW(self ? self->m_searchOldProc : DefWindowProcW, h, msg, wp, lp);
}

LRESULT CALLBACK App::WndProcStatic(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    App* self = reinterpret_cast<App*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    if (msg == WM_NCCREATE) {
        auto* cs = reinterpret_cast<CREATESTRUCTW*>(lp);
        self = reinterpret_cast<App*>(cs->lpCreateParams);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, (LONG_PTR)self);
        self->m_hwnd = hwnd;
    }
    if (!self) return DefWindowProcW(hwnd, msg, wp, lp);
    return self->WndProc(hwnd, msg, wp, lp);
}

LRESULT App::WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
        case WM_CREATE: {
            HMODULE user32 = GetModuleHandleW(L"user32.dll");
            typedef UINT (WINAPI *PFN_GetDpiForWindow)(HWND);
            auto getDpi = user32 ? (PFN_GetDpiForWindow)(void*)GetProcAddress(user32, "GetDpiForWindow") : nullptr;
            m_dpi = getDpi ? (int)getDpi(hwnd) : 96;
            if (m_dpi <= 0) m_dpi = 96;

            CreateFonts();
            m_brSurface = CreateSolidBrush(clr::Surface);

            m_search = CreateWindowExW(0, L"EDIT", L"",
                                       WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
                                       0, 0, 10, 10, hwnd, (HMENU)(INT_PTR)ID_EDIT_SEARCH, m_inst, nullptr);
            if (m_search) {
                m_searchOldProc = (WNDPROC)SetWindowLongPtrW(m_search, GWLP_WNDPROC, (LONG_PTR)&App::SearchProc);
                SendMessageW(m_search, WM_SETFONT, (WPARAM)m_fUi, TRUE);
                SendMessageW(m_search, EM_SETMARGINS, EC_LEFTMARGIN | EC_RIGHTMARGIN, MAKELPARAM(2, 2));
                SendMessageW(m_search, EM_SETLIMITTEXT, 200, 0);
            }

            m_geo.SetOnline(m_geoOnline);
            m_geo.Start();
            m_threat.SetOnline(m_threatOnline || m_rdapOnline || m_vtOnline);
            m_threat.SetRdapOnline(m_rdapOnline);
            m_threat.SetAbuseKey(m_abuseKey);
            m_threat.SetVtKey(m_vtKey);
            m_threat.Start();
            m_cert.SetOnline(m_threatOnline);
            m_cert.Start();
            m_banner.SetOnline(m_bannerOnline);
            m_banner.LoadCache();
            m_banner.Start();
            SetupTray();
            Layout();
            LoadAnomalyBaseline();
            Tick(true);
            SetTimer(hwnd, 1, m_interval, nullptr);

            const std::wstring p = ConfigPath();
            if (GetPrivateProfileIntW(L"ui", L"welcome", 1, p.c_str()) != 0)
                ShowOverlay(Overlay::Welcome);
            return 0;
        }

        case WM_SIZE:
            if (wp == SIZE_MINIMIZED) return 0;
            Layout();
            RebuildView();
            InvalidateRect(hwnd, nullptr, FALSE);
            return 0;

        case WM_GETMINMAXINFO: {
            auto* mmi = reinterpret_cast<MINMAXINFO*>(lp);
            mmi->ptMinTrackSize.x = MulDiv(900, m_dpi, 96);
            mmi->ptMinTrackSize.y = MulDiv(560, m_dpi, 96);
            return 0;
        }

        case WM_DPICHANGED: {
            m_dpi = HIWORD(wp);
            if (m_dpi <= 0) m_dpi = 96;
            CreateFonts();
            RECT* nr = reinterpret_cast<RECT*>(lp);
            SetWindowPos(hwnd, nullptr, nr->left, nr->top, nr->right - nr->left, nr->bottom - nr->top,
                         SWP_NOZORDER | SWP_NOACTIVATE);
            Layout();
            InvalidateRect(hwnd, nullptr, TRUE);
            return 0;
        }

        case WM_TIMER:
            if (wp == 1) {
                const bool onScreen = IsWindowVisible(hwnd) && !IsIconic(hwnd);
                if (onScreen || NowMs() - m_lastRefreshTs >= 5000) {
                    Tick(false);
                    if (onScreen) InvalidateRect(hwnd, nullptr, FALSE);
                    int want = m_interval;
                    if ((int)m_lastTickCostMs * 2 > m_interval)
                        want = (std::min)(10000, (std::max)(m_interval, (int)m_lastTickCostMs * 3));
                    if (!m_effInterval) m_effInterval = m_interval;
                    if (want > m_effInterval || (want < m_effInterval && want <= m_interval)) {
                        m_effInterval = want;
                        SetTimer(hwnd, 1, (UINT)want, nullptr);
                    }
                }
            }
            return 0;

        case WM_ERASEBKGND: return 1;
        case WM_PAINT:      OnPaint(); return 0;

        case WM_LBUTTONDOWN:   OnLButtonDown(GET_X_LPARAM(lp), GET_Y_LPARAM(lp)); return 0;
        case WM_LBUTTONUP:     OnLButtonUp(GET_X_LPARAM(lp), GET_Y_LPARAM(lp)); return 0;
        case WM_LBUTTONDBLCLK: {
            int row = RowAt(GET_Y_LPARAM(lp));
            if (row >= 0) { SetSelection(row); RunAiAnalysis(false); }
            return 0;
        }
        case WM_MOUSEMOVE:  OnMouseMove(GET_X_LPARAM(lp), GET_Y_LPARAM(lp)); return 0;
        case WM_MOUSELEAVE:
            m_hoverRow = -1; m_hotBtn = -1; m_hotCol = -1;
            InvalidateRect(hwnd, nullptr, FALSE);
            return 0;
        case WM_MOUSEWHEEL:
            OnMouseWheel(GET_WHEEL_DELTA_WPARAM(wp), POINT{ GET_X_LPARAM(lp), GET_Y_LPARAM(lp) });
            return 0;
        case WM_CONTEXTMENU:
            OnContextMenu(GET_X_LPARAM(lp), GET_Y_LPARAM(lp));
            return 0;

        case WM_KEYDOWN:  OnKeyDown(wp); return 0;
        case WM_SETFOCUS: InvalidateRect(hwnd, nullptr, FALSE); return 0;

        case WM_CTLCOLOREDIT: {
            HDC dc = (HDC)wp;
            SetTextColor(dc, clr::Text);
            SetBkColor(dc, clr::Surface);
            return (LRESULT)m_brSurface;
        }

        case WM_COMMAND:
            if (LOWORD(wp) == ID_EDIT_SEARCH && HIWORD(wp) == EN_CHANGE) {
                wchar_t buf[256] = L"";
                GetWindowTextW(m_search, buf, 256);
                m_searchText = buf;
                m_query = ParseQuery(m_searchText);
                m_scrollY = 0;
                RebuildView();
                InvalidateRect(hwnd, nullptr, FALSE);
            }
            return 0;

        case WM_APP_AI_DONE:
            OnAiDone(wp != 0, reinterpret_cast<std::wstring*>(lp));
            return 0;

        case WM_APP_TRAY:
            OnTray(lp);
            return 0;

        case WM_SYSCOMMAND:
            if ((wp & 0xFFF0) == SC_MINIMIZE && m_trayAdded) {
                ShowWindow(hwnd, SW_HIDE);
                return 0;
            }
            break;

        case WM_CLOSE:
            ShowWindow(hwnd, SW_HIDE);
            DestroyWindow(hwnd);
            return 0;

        case WM_DESTROY:
            KillTimer(hwnd, 1);
            SavePrefs();
            SaveAnomalyBaseline();
            RemoveTray();
            m_geo.Stop();
            m_threat.Stop();
            m_cert.Stop();
            m_banner.Stop();
            DestroyFonts();
            if (m_brSurface) DeleteObject(m_brSurface);
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, LPWSTR, int nCmdShow) {
    HMODULE user32 = LoadLibraryW(L"user32.dll");
    if (user32) {
        typedef BOOL (WINAPI *PFN_SetCtx)(HANDLE);
        auto setCtx = (PFN_SetCtx)(void*)GetProcAddress(user32, "SetProcessDpiAwarenessContext");
        if (setCtx) setCtx((HANDLE)-4);
        else SetProcessDPIAware();
    }

    HANDLE mtx = CreateMutexW(nullptr, FALSE, L"NetLurker_SingleInstance_Mutex");
    if (mtx && GetLastError() == ERROR_ALREADY_EXISTS) {
        HWND prev = FindWindowW(L"NetLurkerMainWnd", nullptr);
        if (prev) {
            ShowWindow(prev, SW_SHOW);
            ShowWindow(prev, SW_RESTORE);
            SetForegroundWindow(prev);
        }
        CloseHandle(mtx);
        if (user32) FreeLibrary(user32);
        return 0;
    }

    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    GdiPlusInit();
    INITCOMMONCONTROLSEX icc;
    icc.dwSize = sizeof(icc);
    icc.dwICC  = ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icc);

    App app;
    g_app = &app;
    int rc = 1;
    if (app.Init(hInst, nCmdShow)) {
        MSG msg;
        while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        rc = 0;
    } else {
        MessageBoxW(nullptr, Tr(L"Could not create the window."), L"NetLurker", MB_ICONERROR);
    }

    GdiPlusShutdown();
    WSACleanup();
    if (mtx) CloseHandle(mtx);
    if (user32) FreeLibrary(user32);
    return rc;
}

void App::FollowUpAi(int q) {
    if (m_lastAiPrompt.empty()) return;
    {
        std::lock_guard<std::mutex> lk(m_aiMtx);
        if (m_aiBusy) return;
    }
    AiConfig cfg = LoadAiConfig();
    if (!cfg.Valid()) {
        Toast(Tr(L"Add an API key in Settings to use AI follow-ups."), clr::Yellow);
        return;
    }
    std::wstring prompt;
    if (q == 2) {
        std::wstring blk = Tr(L"Behavioral baseline (connections per minute):");
        bool any = false;
        for (const auto& kv : m_anomStats) {
            if (kv.second.n < 24) continue;
            if (!m_lastAiProc.empty() && kv.first != m_lastAiProc) continue;
            wchar_t ln[220];
            swprintf(ln, 220, Tr(L"\n%s: baseline ~%.1f (variance %.2f), latest %.1f"),
                     kv.first.c_str(), kv.second.ema, kv.second.var, kv.second.lastRate);
            blk += ln;
            any = true;
        }
        if (!any)
            blk = Tr(L"(No baseline for this process yet; NetLurker can compare after collecting at least 24 samples.)");
        prompt = m_lastAiPrompt + L"\n\n" + blk + L"\n\n" +
            Tr(L"Question: Is the current network behavior consistent with this process's normal baseline? Is there a meaningful deviation? Assess evidence-based and cite sources where available.");
    } else {
        prompt = m_lastAiPrompt + L"\n\n" +
            (q == 0 ? Tr(L"Question: Why might this connection be suspicious? Answer briefly, evidence-based.")
                    : Tr(L"Question: What should I do about this finding? Answer step by step, in priority order."));
    }
    {
        std::lock_guard<std::mutex> lk(m_aiMtx);
        if (m_aiBusy) return;
        m_aiBusy = true;
        m_aiTitle = (q == 0) ? Tr(L"Why is this suspicious?") : (q == 1 ? Tr(L"What should I do?") : Tr(L"Deviation from normal?"));
        m_aiText  = Tr(L"Analyzing…");
    }
    Layout();
    InvalidateRect(m_hwnd, nullptr, FALSE);
    HWND hwnd = m_hwnd;
    AnalyzeAsync(cfg, prompt, [hwnd](bool ok, std::wstring text) {
        PostAiResult(hwnd, ok, std::move(text));
    });
}
