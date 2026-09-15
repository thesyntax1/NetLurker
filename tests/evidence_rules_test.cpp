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

    for (int mask=0; mask<32; ++mask) {
        const bool threat=mask&1, rdap=mask&2, abuse=mask&4, vt=mask&8, plugins=mask&16;
        const auto plan=nl::PlanSources(threat,rdap,abuse,vt,plugins);
        assert(plan.dnsbl==threat && plan.pdns==threat && plan.abuse==(threat&&abuse));
        assert(plan.rdap==rdap && plan.vt==vt && plan.plugins==(threat&&plugins));
    }
    assert(nl::CsvText(L"=1+1")==L"'=1+1");
    assert(nl::CsvText(L" \t@SUM(1)")==L"' \t@SUM(1)");
    assert(nl::CsvText(L"ACME;\"Co\"")==L"\"ACME;\"\"Co\"\"\"");
    bool flag = false;
    assert(nl::json::GetBool("{\"isTor\": true}", "isTor", flag) && flag);
    assert(nl::json::GetBool("{\"isTor\": false}", "isTor", flag) && !flag);
    assert(!nl::json::GetBool("{\"isTor\": 1}", "isTor", flag));
    assert(!nl::json::GetBool("{}", "isTor", flag));
    assert(nl::LabelCsvOrigin(L"app;pid\r\nexample;42\r\n",true)==L"data_source;app;pid\r\ndemo;example;42\r\n");
    assert(nl::LabelCsvOrigin(L"app;pid\nexample;42",false)==L"data_source;app;pid\nlive;example;42");
    assert(nl::LabelCsvOrigin(L"",true).empty());
    std::cout << "Evidence rules: DNSBL errors, version boundaries, provider merge, JSON booleans passed\n";
}
