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
    assert(GetNextDlgTabItem(dialog, GetDlgItem(body, IDC_ED_ENDPOINT), FALSE) == GetDlgItem(body, IDC_ED_MODEL));
    assert(GetNextDlgTabItem(dialog, GetDlgItem(body, IDC_ED_MODEL), FALSE) == GetDlgItem(body, IDC_ED_INTERVAL));
    for (int id : {IDC_ED_KEY, IDC_ED_ABUSEKEY, IDC_ED_VTKEY})
        assert(GetWindowLongPtrW(GetDlgItem(body, id), GWL_STYLE) & ES_PASSWORD);
    for (UINT dpi : {96u, 120u, 144u, 192u, 288u}) {
        for (int height : {240, 400, 700}) {
            layout->ChangeDpi(dpi, {0, 0, 380, height});
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
