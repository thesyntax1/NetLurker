#include "firewall.h"

#include <windows.h>
#include <netfw.h>
#include <objbase.h>
#include <oleauto.h>

namespace {

const wchar_t* kPrefix = L"NetLurker Block ";

struct ComScope {
    bool owned = false;
    ComScope() {
        HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
        owned = SUCCEEDED(hr);
        if (hr == RPC_E_CHANGED_MODE) owned = false;
    }
    ~ComScope() { if (owned) CoUninitialize(); }
};

INetFwPolicy2* OpenPolicy() {
    INetFwPolicy2* pol = nullptr;
    HRESULT hr = CoCreateInstance(__uuidof(NetFwPolicy2), nullptr, CLSCTX_INPROC_SERVER,
                                  __uuidof(INetFwPolicy2), (void**)&pol);
    if (FAILED(hr)) return nullptr;
    return pol;
}

}

std::wstring FwRuleNameFor(const std::wstring& ip) {
    return std::wstring(kPrefix) + ip;
}

bool FwAvailable() {
    ComScope com;
    INetFwPolicy2* pol = OpenPolicy();
    if (!pol) return false;
    pol->Release();
    return true;
}

bool FwListNetLurkerRules(std::vector<FwRule>& out) {
    out.clear();
    ComScope com;
    INetFwPolicy2* pol = OpenPolicy();
    if (!pol) return false;

    INetFwRules* rules = nullptr;
    bool ok = false;
    if (SUCCEEDED(pol->get_Rules(&rules)) && rules) {
        IUnknown* unk = nullptr;
        if (SUCCEEDED(rules->get__NewEnum(&unk)) && unk) {
            IEnumVARIANT* en = nullptr;
            if (SUCCEEDED(unk->QueryInterface(__uuidof(IEnumVARIANT), (void**)&en)) && en) {
                ok = true;
                VARIANT v;
                VariantInit(&v);
                ULONG fetched = 0;
                while (en->Next(1, &v, &fetched) == S_OK && fetched == 1) {
                    INetFwRule* rule = nullptr;
                    if (v.vt == VT_DISPATCH && v.pdispVal &&
                        SUCCEEDED(v.pdispVal->QueryInterface(__uuidof(INetFwRule), (void**)&rule)) && rule) {
                        BSTR name = nullptr;
                        if (SUCCEEDED(rule->get_Name(&name)) && name) {
                            std::wstring n(name, SysStringLen(name));
                            if (n.compare(0, wcslen(kPrefix), kPrefix) == 0) {
                                FwRule r;
                                r.name = n;
                                r.remoteIp = n.substr(wcslen(kPrefix));
                                VARIANT_BOOL enabled = VARIANT_TRUE;
                                rule->get_Enabled(&enabled);
                                r.enabled = (enabled != VARIANT_FALSE);
                                BSTR addrs = nullptr;
                                if (SUCCEEDED(rule->get_RemoteAddresses(&addrs)) && addrs) {
                                    std::wstring a(addrs, SysStringLen(addrs));
                                    if (!a.empty() && a != L"*") {
                                        const size_t slash = a.find(L'/');
                                        r.remoteIp = (slash == std::wstring::npos) ? a : a.substr(0, slash);
                                    }
                                    SysFreeString(addrs);
                                }
                                out.push_back(std::move(r));
                            }
                            SysFreeString(name);
                        }
                        rule->Release();
                    }
                    VariantClear(&v);
                    VariantInit(&v);
                }
                en->Release();
            }
            unk->Release();
        }
        rules->Release();
    }
    pol->Release();
    return ok;
}

bool FwRemoveRule(const std::wstring& name) {
    ComScope com;
    INetFwPolicy2* pol = OpenPolicy();
    if (!pol) return false;
    INetFwRules* rules = nullptr;
    bool ok = false;
    if (SUCCEEDED(pol->get_Rules(&rules)) && rules) {
        BSTR bn = SysAllocString(name.c_str());
        if (bn) {
            ok = SUCCEEDED(rules->Remove(bn));
            SysFreeString(bn);
        }
        rules->Release();
    }
    pol->Release();
    return ok;
}
