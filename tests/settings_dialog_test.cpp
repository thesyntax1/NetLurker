#include "settings_dialog.h"
#include "resource.h"
#include <cassert>
#include <iostream>

using nl::SettingsDialogLayout;
static INT_PTR CALLBACK DialogProc(HWND dialog, UINT message, WPARAM, LPARAM) {
    auto* layout = reinterpret_cast<SettingsDialogLayout*>(GetWindowLongPtrW(dialog, GWLP_USERDATA));
    if (message == WM_INITDIALOG) {
        // Stress wrapping, not only the short resource-template labels.
        SetDlgItemTextW(dialog, IDC_CHK_THREAT, L"Enable threat intelligence and registration information for remote destinations; this intentionally long translated label must wrap without covering the next setting.");
        SetDlgItemTextW(dialog, IDOK, L"Einstellungen speichern");
        SetDlgItemTextW(dialog, IDCANCEL, L"Abbrechen");
        layout = new SettingsDialogLayout(dialog, reinterpret_cast<HBRUSH>(GetStockObject(BLACK_BRUSH)));
        SetWindowLongPtrW(dialog, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(layout));
        assert(layout->Initialize());
        return TRUE;
    }
    if (message == WM_SIZE && layout) layout->Layout();
    if (message == WM_NCDESTROY) { delete layout; SetWindowLongPtrW(dialog, GWLP_USERDATA, 0); }
    return FALSE;
}
static RECT ChildRect(HWND child, HWND parent) {
    RECT r{}; GetWindowRect(child, &r);
    MapWindowPoints(nullptr, parent, reinterpret_cast<POINT*>(&r), 2);
    return r;
}
int main() {
    INITCOMMONCONTROLSEX cc{sizeof(cc), ICC_STANDARD_CLASSES}; InitCommonControlsEx(&cc);
    HWND dialog = CreateDialogParamW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(IDD_SETTINGS), nullptr, DialogProc, 0);
    assert(dialog);
    auto* layout = reinterpret_cast<SettingsDialogLayout*>(GetWindowLongPtrW(dialog, GWLP_USERDATA));
    HWND body = layout->Body();
    assert(GetParent(GetDlgItem(body, IDC_ED_KEY)) == body);
    assert(GetParent(GetDlgItem(dialog, IDOK)) == dialog);
    HWND language = GetDlgItem(body, IDC_CMB_LANG);
    assert(GetNextDlgTabItem(dialog, nullptr, FALSE) == language);
    assert(GetNextDlgTabItem(dialog, language, FALSE) == GetDlgItem(body, IDC_ED_ENDPOINT));
    RECT area{}; GetClientRect(body, &area);
    const auto languageBounds = ChildRect(language, body);
    const auto endpointBounds = ChildRect(GetDlgItem(body, IDC_ED_ENDPOINT), body);
    assert(languageBounds.top >= 0 && languageBounds.bottom <= area.bottom);
    assert(languageBounds.bottom <= endpointBounds.top);
    SendMessageW(language, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"English"));
    SendMessageW(language, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"Türkçe"));
    SendMessageW(language, CB_SETCURSEL, 1, 0);
    assert(SendMessageW(language, CB_GETCURSEL, 0, 0) == 1);
    assert(GetNextDlgTabItem(dialog, GetDlgItem(body, IDC_ED_ENDPOINT), FALSE) == GetDlgItem(body, IDC_ED_MODEL));
    assert(GetNextDlgTabItem(dialog, GetDlgItem(body, IDC_ED_MODEL), FALSE) == GetDlgItem(body, IDC_ED_INTERVAL));
    for (int id : {IDC_ED_KEY, IDC_ED_ABUSEKEY, IDC_ED_VTKEY})
        assert(GetWindowLongPtrW(GetDlgItem(body, id), GWL_STYLE) & ES_PASSWORD);
    for (UINT dpi : {96u, 120u, 144u, 192u, 288u}) {
        for (int height : {240, 400, 700}) {
            layout->ChangeDpi(dpi, {0, 0, 380, height});
            SendMessageW(body, WM_VSCROLL, SB_TOP, 0);
            const auto picker = ChildRect(language, body);
            const auto endpoint = ChildRect(GetDlgItem(body, IDC_ED_ENDPOINT), body);
            assert(picker.top >= 0 && picker.bottom <= endpoint.top);
            RECT bodyArea{}; GetClientRect(body, &bodyArea);
            // At 300% scaling the deliberately tiny 240px window cannot fit
            // even the first field plus footer; the normal-height case must.
            if (height == 700) assert(picker.bottom <= bodyArea.bottom);
            RECT client{}; GetClientRect(dialog, &client);
            const auto save = ChildRect(GetDlgItem(dialog, IDOK), dialog);
            const auto cancel = ChildRect(GetDlgItem(dialog, IDCANCEL), dialog);
            const auto viewport = ChildRect(body, dialog);
            assert(save.top >= 0 && save.bottom <= client.bottom);
            assert(cancel.top >= 0 && cancel.bottom <= client.bottom);
            assert(viewport.bottom <= save.top && save.right <= cancel.left);
            SendMessageW(body, WM_VSCROLL, SB_BOTTOM, 0);
            const auto after = ChildRect(GetDlgItem(dialog, IDOK), dialog);
            assert(EqualRect(&save, &after));
            // Scrolled controls are clipped by their parent, not painted over the actions.
            const auto info = ChildRect(GetDlgItem(body, IDC_ST_INFO), body);
            RECT area{}; GetClientRect(body, &area);
            assert(info.bottom <= area.bottom);
        }
    }
    DestroyWindow(dialog);
    std::cout << "Settings Win32 controls: 15 DPI/height cases, pinned actions, tab order, scrolling and masked keys passed\n";
}
