#include "provider_evidence.h"
#include "iso_date.h"
#include <cassert>
#include <iostream>
using namespace nl;
int main() {
    strictjson::Value value;
    for (auto bad : {"{\"x\":NaN}", "{\"x\":Infinity}", "{\"x\":1e999}", "{\"x\":01}", "{\"x\":truejunk}", "{\"x\":1,}", "{\"x\":1,\"x\":2}", "{\"x\":\"\\uD800\"}", "{} junk", "[{},", "{\"x\":2"}) assert(!strictjson::Parse(bad,value));
    assert(strictjson::Parse("{\"x\": {\"n\": 2}, \"text\": \"} [\\\"\"}",value));
    int n=99; assert(!value.At("n").Integer(n) && n==99);
    provider::Abuse abuse;
    assert(provider::ReadAbuse(R"({"data":{"ipAddress":"8.8.8.8","abuseConfidenceScore":0,"totalReports":0,"isTor":false}})","8.8.8.8",abuse));
    assert(abuse.abuseScore==0);
    for(auto body : {R"({"data":{"ipAddress":"8.8.4.4","abuseConfidenceScore":0,"totalReports":0}})", R"({"data":{"ipAddress":"8.8.8.8","abuseConfidenceScore":"0","totalReports":0}})", R"({"data":{"ipAddress":"8.8.8.8","abuseConfidenceScore":1.5,"totalReports":0}})", R"({"data":{"reportedAddress":[]}})", R"({"abuseConfidenceScore":0,"data":{"ipAddress":"8.8.8.8","totalReports":0}})"}) assert(!provider::ReadAbuse(body,"8.8.8.8",abuse));
    const std::string prefix=R"({"data":{"id":"8.8.8.8","type":"ip_address","attributes":{"reputation":-2,"last_analysis_stats":)";
    provider::VirusTotal vt;
    assert(provider::ReadVt(prefix+R"({"malicious":2,"suspicious":1,"harmless":3,"undetected":4,"timeout":100}}}})","8.8.8.8",vt));
    assert(vt.total==10 && vt.reputation==-2);
    for(auto stats : {"{}", R"({"malicious":-1,"suspicious":0,"harmless":0,"undetected":0})", R"({"malicious":0,"suspicious":0,"harmless":0,"undetected":0})", R"({"malicious":2147483647,"suspicious":1,"harmless":1,"undetected":1})"}) assert(!provider::ReadVt(prefix+stats+"}}}","8.8.8.8",vt));
    provider::PassiveDns pdns;
    assert(provider::ReadPdns("[]","8.8.8.8",pdns) && pdns.records==0);
    assert(!provider::ReadPdns(R"({"error":"not authorized"})","8.8.8.8",pdns));
    assert(!provider::ReadPdns("[{},null]","8.8.8.8",pdns));
    std::string row=R"({"rrname":"dns.google","rrtype":"A","rdata":"8.8.8.8","time_last":1700000000})";
    assert(provider::ReadPdns(row+"\n"+row,"8.8.8.8",pdns) && pdns.records==2 && pdns.names.size()==1);
    assert(!provider::ReadPdns(row,"8.8.4.4",pdns));
    assert(IsoEpoch("2023-11-15T01:13:20+03:00")==1700000000ull);
    assert(IsoEpoch("2023-11-14T17:13:20.999-05:00")==1700000000ull);
    for(auto date : {"2023-02-30T12:00:00Z","2023-13-01T12:00:00Z","2023-11-14T25:00:00Z","2023-11-14T12:00:00Zjunk"}) assert(IsoEpoch(date)==0);
    std::cout << "Provider evidence: strict schema, identity, unknown vs zero, PDNS arrays/NDJSON, VT denominator/overflow and ISO dates passed\n";
}
