#include "evidence_rules.h"
#include "json.h"
#include <cassert>
#include <iostream>

struct Evidence {
    int abuseScore = -1, totalReports = 0;
    unsigned long long lastReport = 0;
    bool isTor = false, isWhitelisted = false;
    std::wstring dnsbl, rdapOrg;
    int vtMalicious = 0;
};

int main() {
    for (unsigned code : {252u, 254u, 255u}) {
        assert(!nl::DnsblListingCode(true, 127, 255, 255, code));
        assert(!nl::DnsblListingCode(false, 127, 255, 255, code));
    }
    assert(nl::DnsblListingCode(true, 127, 0, 0, 4));
    assert(nl::DnsblListingCode(false, 127, 0, 0, 2));
    assert(!nl::DnsblListingCode(false, 8, 8, 8, 8));
    assert(!nl::DnsblListingCode(true, 127, 0, 0, 255));
    assert(!nl::BannerVersionMatch(L"nginx/1.25.3", L"nginx/1.2"));
    assert(!nl::BannerVersionMatch(L"tomcat/10.1", L"tomcat/1"));
    assert(nl::BannerVersionMatch(L"nginx/1.2.9", L"nginx/1.2"));
    assert(nl::BannerVersionMatch(L"apache/2.2.15", L"apache/2.2"));
    assert(nl::BannerVersionMatch(L"apache/1.3.41", L"apache/1."));
    assert(!nl::BannerVersionMatch(L"nginx/1.25.3", L""));

    Evidence combined, abuse;
    combined.dnsbl = L"test-list";
    combined.rdapOrg = L"Test organisation";
    combined.vtMalicious = 4;
    abuse.abuseScore = 80;
    abuse.totalReports = 12;
    abuse.isTor = true;
    nl::MergeAbuseEvidence(combined, abuse);
    assert(combined.abuseScore == 80 && combined.totalReports == 12 && combined.isTor);
    assert(combined.dnsbl == L"test-list" && combined.rdapOrg == L"Test organisation");
    assert(combined.vtMalicious == 4);

    bool flag = false;
    assert(nl::json::GetBool("{\"isTor\": true}", "isTor", flag) && flag);
    assert(nl::json::GetBool("{\"isTor\": false}", "isTor", flag) && !flag);
    assert(!nl::json::GetBool("{\"isTor\": 1}", "isTor", flag));
    assert(!nl::json::GetBool("{}", "isTor", flag));
    std::cout << "Evidence rules: DNSBL errors, version boundaries, provider merge, JSON booleans passed\n";
}
