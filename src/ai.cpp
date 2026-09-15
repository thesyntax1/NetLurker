#include "ai.h"
#include "config_store.h"
#include "i18n.h"
#include "http.h"
#include "json.h"
#include <thread>
#include <sstream>

namespace nl {

static const wchar_t* ReplyLanguageName() {
    const std::wstring c = I18nLanguage();
    if (c == L"tr") return L"Turkish";
    if (c == L"es") return L"Spanish";
    if (c == L"de") return L"German";
    if (c == L"fr") return L"French";
    if (c == L"ja") return L"Japanese";
    if (c == L"zh") return L"Simplified Chinese";
    if (c == L"pt") return L"Portuguese";
    return L"English";
}

static std::wstring AnswerRules() {
    std::wstring s = Tr(L"Answer concisely, in bullet points. Do not invent facts; state clearly where you are unsure.\n");
    s += L"Answer language: ";
    s += ReplyLanguageName();
    s += L".";
    return s;
}

std::wstring ConfigPath() { return AppDataDir() + L"\\config.ini"; }

std::wstring AiEnvironmentKey() {
    wchar_t env[1024]{};
    const DWORD length = GetEnvironmentVariableW(L"OPENAI_API_KEY", env, 1024);
    return length > 0 && length < 1024 ? Trim(env) : L"";
}

AiConfig LoadAiConfig(bool includeEnvironmentKey) {
    AiConfig cfg;
    const std::wstring path = ConfigPath();
    wchar_t buf[1024];

    GetPrivateProfileStringW(L"ai", L"endpoint", cfg.endpoint.c_str(), buf, 1024, path.c_str());
    cfg.endpoint = Trim(buf);
    GetPrivateProfileStringW(L"ai", L"model", cfg.model.c_str(), buf, 1024, path.c_str());
    cfg.model = Trim(buf);
    GetPrivateProfileStringW(L"ai", L"api_key", L"", buf, 1024, path.c_str());
    cfg.apiKey = Trim(buf);

    if (includeEnvironmentKey && cfg.apiKey.empty()) cfg.apiKey = AiEnvironmentKey();
    if (cfg.endpoint.empty()) cfg.endpoint = L"https://api.openai.com/v1/chat/completions";
    if (cfg.model.empty())    cfg.model    = L"gpt-4o-mini";
    return cfg;
}

bool SaveAiConfig(const AiConfig& cfg) {
    return UpdateIniAtomically(ConfigPath(), {
        {L"ai", L"endpoint", cfg.endpoint}, {L"ai", L"model", cfg.model}, {L"ai", L"api_key", cfg.apiKey}
    });
}

std::wstring BuildAnalysisPrompt(const Conn& c, const std::vector<Conn>& all, const ProcContext& pc) {
    std::wostringstream os;
    os << Tr(L"The following network connection was detected on a Windows system. ")
       << Tr(L"Evaluate it like a security analyst.\n\n")
       << Tr(L"Answer in EXACTLY this structure (keep the headers, be brief and evidence-based):\nKARAR: <one sentence>\nGUVEN: <%>\nNEDEN: <3-5 bullets>\nENDISELER: <bullets>\nONERI: <single recommendation>\nADIMLAR: <numbered steps>\n\n")
       << Tr(L"Process      : ") << c.procName << L" (PID " << c.pid << L")\n"
       << Tr(L"Full path    : ") << (c.procPath.empty() ? Tr(L"(unknown)") : c.procPath) << L"\n"
       << Tr(L"Protocol     : ") << c.ProtoText() << L"\n"
       << Tr(L"Local addr   : ") << c.LocalText() << L"\n"
       << Tr(L"Remote addr  : ") << c.RemoteText() << L"\n"
       << Tr(L"State        : ") << c.StateText() << L"\n"
       << Tr(L"Country      : ") << (c.country.empty() ? Tr(L"(unknown)") : c.country) << L"\n"
       << Tr(L"Org / ISP    : ") << (c.org.empty() ? Tr(L"(unknown)") : c.org) << L"\n"
       << Tr(L"ASN          : ") << (c.asn.empty() ? Tr(L"(unknown)") : c.asn) << L"\n"
       << Tr(L"Reverse DNS  : ") << (c.host.empty() ? Tr(L"(unknown)") : c.host) << L"\n"
       << Tr(L"Current rate : download ") << FormatBytesPerSec(c.rateIn)
       << Tr(L", upload ") << FormatBytesPerSec(c.rateOut) << L"\n"
       << Tr(L"Publisher    : ") << (c.publisher.empty() ? Tr(L"(unknown)") : c.publisher) << L"\n"
       << Tr(L"Signature    : ") << SignStateText(c.sign) << L"\n"
       << (c.services.empty() ? L"" : (Tr(L"Services     : ") + c.services + L"\n"))
       << Tr(L"User         : ") << (c.user.empty() ? Tr(L"(unknown)") : c.user) << L"\n"
       << Tr(L"Hosting      : ") << (c.isHosting ? Tr(L"datacenter/cloud") : Tr(L"no"))
       << (c.isProxy ? Tr(L", proxy/VPN") : L"") << (c.isMobile ? Tr(L", mobile network") : L"") << L"\n"
       << (c.module.empty() ? L"" : (Tr(L"Socket module: ") + c.module + L"\n"))
       << (c.threatScore >= 0 ? (Tr(L"AbuseIPDB    : ") + std::to_wstring(c.threatScore) + L"/100, " +
                                 std::to_wstring(c.threatReports) + Tr(L" reports\n")) : L"")
       << (c.threatDnsbl.empty() || c.threatDnsbl == L"—" ? L"" :
           (Tr(L"DNS blacklist: ") + c.threatDnsbl + L"\n"))
       << (c.threatPdns > 0 ? (Tr(L"CIRCL passive DNS: ") + std::to_wstring(c.threatPdns) + Tr(L" records") +
                               (c.threatPdnsNames.empty() ? L"" : (L" (" + c.threatPdnsNames + L")")) + L"\n") : L"")
       << (c.certIssuer.empty() ? L"" :
           (Tr(L"TLS certificate: ") + c.certIssuer + (c.certSubject.empty() ? L"" : (L" / CN=" + c.certSubject)) +
            (c.certSelfSigned ? Tr(L" [self-signed]") : L"") + (c.certExpired ? Tr(L" [expired]") : L"") +
            (c.certMismatch ? Tr(L" [rDNS mismatch]") : L"") + L"\n"))
       << (c.rdapOrg.empty() ? L"" :
           (Tr(L"RDAP ownership: ") + c.rdapOrg + (c.rdapCidr.empty() ? L"" : (L" [" + c.rdapCidr + L"]")) +
            (c.rdapRegistered ? (Tr(L", registered: ") + std::to_wstring(c.rdapRegistered)) : L"") + L"\n"))
       << (c.vtTotal > 0 ?
           (Tr(L"VirusTotal: ") + std::to_wstring(c.vtMalicious) + L"/" + std::to_wstring(c.vtTotal) +
            Tr(L" engines malicious, ") + std::to_wstring(c.vtSuspicious) + Tr(L" suspicious, community score ") +
            std::to_wstring(c.vtReputation) + L"\n") : L"")
       << (c.domain.empty() ? L"" : (Tr(L"DNS domain: ") + c.domain + L"\n"))
       << (c.banner.empty() ? L"" : (Tr(L"HTTP banner : ") + c.banner + L"\n"))
       << Tr(L"Local risk score: ") << c.riskScore << L"/100\n"
       << Tr(L"Local risk note : ") << c.riskReason << L"\n\n";

    if (pc.valid) {
        os << Tr(L"— Process dossier —\n");
        if (!pc.product.empty())   os << Tr(L"Product      : ") << pc.product
                                      << (pc.version.empty() ? L"" : (L" v" + pc.version)) << L"\n";
        if (!pc.cmdline.empty())   os << Tr(L"Command line : ") << pc.cmdline << L"\n";
        if (!pc.parent.empty())    os << Tr(L"Parent proc  : ") << pc.parent << L"\n";
        if (!pc.integrity.empty()) os << Tr(L"Integrity   : ") << pc.integrity
                                      << (pc.elevated ? Tr(L" (elevated)") : L"") << L"\n";
        if (!pc.sha256.empty() && pc.sha256.size() == 64)
            os << L"SHA-256     : " << pc.sha256 << L"\n";
        wchar_t rb[200];
        swprintf(rb, 200, Tr(L"Resources   : CPU %.1f%%, RAM %s, %lu threads%s\n"),
                 pc.cpu, FormatBytes(pc.ram).c_str(), pc.threads,
                 pc.suspended ? Tr(L", SUSPENDED") : L"");
        os << rb;
        if (pc.uptimeMs) os << Tr(L"Uptime      : ") << (pc.uptimeMs / 60000ull) << Tr(L" minutes\n");
        os << L"\n";
    }

    int same = 0;
    for (const auto& o : all) if (o.pid == c.pid) ++same;
    os << Tr(L"Total open connections of the same process: ") << same << L"\n\n";

    os << Tr(L"Questions:\n")
       << Tr(L"1) Why might this process be talking to this IP/port? Give the 2-3 most likely legitimate explanations.\n")
       << Tr(L"2) How likely is it malicious/unwanted? Give a risk score from 0 to 100.\n")
       << Tr(L"3) What concrete steps should the user take?\n")
       << AnswerRules();
    return os.str();
}

void AnalyzeAsync(const AiConfig& cfg, const std::wstring& prompt,
                  std::function<void(bool, std::wstring)> done) {
    std::thread([cfg, prompt, done]() {
        if (!cfg.Valid()) {
            done(false, Tr(L"AI is not configured. Enter an API key in Settings or define the OPENAI_API_KEY environment variable."));
            return;
        }
        const std::string sysMsg =
            std::string("You are an experienced network security analyst. Be concise, factual and "
                        "evidence-based; never invent details. Always answer in ") +
            Narrow(ReplyLanguageName()) + ".";
        std::string body =
            std::string("{\"model\":\"") + json::Escape(Narrow(cfg.model)) + "\","
            "\"temperature\":0.2,"
            "\"messages\":["
            "{\"role\":\"system\",\"content\":\"" + json::Escape(sysMsg) + "\"},"
            "{\"role\":\"user\",\"content\":\"" + json::Escape(Narrow(prompt)) + "\"}]}";

        auto res = http::Request("POST", Narrow(cfg.endpoint), body,
                                 "application/json", Narrow(cfg.apiKey), 60000);
        if (!res.ok) {
            std::string msg;
            if (!json::FindStringDeep(res.body, "message", msg) || msg.empty()) msg = res.error;
            done(false, Tr(L"AI request failed: ") + Widen(msg));
            return;
        }
        std::string content;
        if (!json::FindStringDeep(res.body, "content", content) || content.empty()) {
            done(false, Tr(L"The AI response could not be parsed."));
            return;
        }
        done(true, Widen(content));
    }).detach();
}

std::wstring BuildBulkPrompt(const std::vector<Conn>& conns) {
    std::wostringstream os;
    os << Tr(L"The following suspicious network connections were detected on a Windows system. ")
       << Tr(L"Evaluate it like a security analyst.\n\n");
    int i = 1;
    for (const auto& c : conns) {
        os << i++ << L") " << c.procName << L" (PID " << c.pid << L") -> "
           << c.RemoteText() << L"  " << c.ProtoText() << L" " << c.StateText() << L"\n"
           << Tr(L"   path: ") << (c.procPath.empty() ? Tr(L"(unknown)") : c.procPath) << L"\n"
           << Tr(L"   signature: ") << SignStateText(c.sign)
           << Tr(L" | publisher: ") << (c.publisher.empty() ? Tr(L"(none)") : c.publisher) << L"\n"
           << Tr(L"   location: ") << (c.country.empty() ? Tr(L"(unknown)") : c.country)
           << Tr(L" | org: ") << (c.org.empty() ? Tr(L"(unknown)") : c.org)
           << (c.host.empty() ? L"" : (L" | dns: " + c.host)) << L"\n"
           << Tr(L"   rate: in ") << FormatBytesPerSec(c.rateIn)
           << L" / out " << FormatBytesPerSec(c.rateOut)
           << Tr(L" | local score: ") << c.riskScore << L"/100 (" << c.riskReason << L")\n\n";
        if (i > 25) break;
    }
    os << Tr(L"Tasks:\n")
       << Tr(L"1) Give a one-sentence assessment and a 0-100 risk score for each connection.\n")
       << Tr(L"2) List the 3 most dangerous ones in priority order.\n")
       << Tr(L"3) Write the concrete steps the user should take.\n")
       << AnswerRules();
    return os.str();
}

std::wstring LocalHeuristicAnalysis(const Conn& c) {
    std::wostringstream os;
    os << Tr(L"OFFLINE HEURISTIC ANALYSIS (local rule engine, not a language model)\n\n");
    os << Tr(L"Process: ") << c.procName << L"  (PID " << c.pid << L")\n";
    if (!c.procPath.empty()) os << Tr(L"Path : ") << c.procPath << L"\n";
    os << Tr(L"Target: ") << c.RemoteText() << L"  " << c.ProtoText() << L"\n";
    if (!c.country.empty()) os << Tr(L"Location: ") << c.country << (c.org.empty() ? L"" : (L" / " + c.org)) << L"\n";
    if (!c.host.empty() && c.host != L"—") os << L"DNS  : " << c.host << L"\n";
    if (!c.publisher.empty()) os << Tr(L"Signature : ") << SignStateText(c.sign) << L" — " << c.publisher << L"\n";
    else                      os << Tr(L"Signature : ") << SignStateText(c.sign) << L"\n";
    if (!c.services.empty())  os << Tr(L"Service: ") << c.services << L"\n";
    if (!c.module.empty())    os << Tr(L"Module: ") << c.module << L"\n";
    if (c.threatScore >= 0) {
        os << L"AbuseIPDB: " << c.threatScore << L"/100";
        if (c.threatReports) os << L" (" << c.threatReports << Tr(L" reports)");
        os << L"\n";
    }
    if (!c.threatDnsbl.empty() && c.threatDnsbl != L"—")
        os << Tr(L"Blacklist: ") << c.threatDnsbl << L"\n";
    if (c.threatPdns > 0) {
        os << Tr(L"Passive DNS: ") << c.threatPdns << Tr(L" records");
        if (!c.threatPdnsNames.empty()) os << L" (" << c.threatPdnsNames << L")";
        os << L"\n";
    }
    if (!c.certIssuer.empty()) {
        os << Tr(L"Certificate: ") << c.certIssuer << (c.certSubject.empty() ? L"" : (L" / CN=" + c.certSubject));
        if (c.certSelfSigned) os << Tr(L" [self-signed]");
        if (c.certExpired)    os << Tr(L" [expired]");
        if (c.certMismatch)   os << Tr(L" [rDNS mismatch]");
        os << L"\n";
    }
    if (!c.rdapOrg.empty()) {
        os << Tr(L"RDAP: ") << c.rdapOrg;
        if (!c.rdapCidr.empty()) os << L" [" << c.rdapCidr << L"]";
        os << L"\n";
    }
    if (c.vtTotal > 0)
        os << Tr(L"VirusTotal: ") << c.vtMalicious << L"/" << c.vtTotal << Tr(L" malicious, ")
           << c.vtSuspicious << Tr(L" suspicious\n");
    if (!c.domain.empty()) os << Tr(L"Domain: ") << c.domain << L"\n";
    if (!c.banner.empty()) os << Tr(L"Banner: ") << c.banner << L"\n";
    os << Tr(L"\nAssessment:\n");

    unsigned short p = c.IsListening() ? c.localPort : c.remotePort;
    const wchar_t* svc = PortServiceName(p);
    if (svc) os << Tr(L"• Port ") << p << Tr(L" = ") << svc << Tr(L" (a common, standard service).\n");
    else     os << Tr(L"• Port ") << p << Tr(L" does not belong to a known service; it may be an application-specific protocol.\n");

    if (c.sign == SignState::Unsigned || c.sign == SignState::Invalid)
        os << Tr(L"• The executable is not digitally signed / its signature is invalid.\n");
    if (c.isHosting) os << Tr(L"• The destination is a data center/cloud IP (C2 servers are often hosted there).\n");
    if (c.isProxy)   os << Tr(L"• The destination is flagged as a proxy/VPN/Tor exit node.\n");

    switch (c.risk) {
        case Risk::Danger:
            os << Tr(L"• HIGH RISK: ") << c.riskReason << L"\n"
               << Tr(L"• Recommended: terminate the process, run a full disk scan, block the destination IP in the firewall and check the file hash on VirusTotal.\n");
            break;
        case Risk::Warn:
            os << Tr(L"• CAUTION: ") << c.riskReason << L"\n"
               << Tr(L"• Recommended: verify the signature and location of the process; block the connection if it is not needed.\n");
            break;
        case Risk::Info:
            os << Tr(L"• INFO: ") << c.riskReason << L"\n"
               << Tr(L"• Usually harmless, but you should still recognize what this process is.\n");
            break;
        default:
            os << Tr(L"• No obvious anomaly.\n");
    }
    os << Tr(L"\nThis text was produced by fixed local rules; no language model was used. For deeper analysis, set an AI API key in Settings.");
    return os.str();
}

}
